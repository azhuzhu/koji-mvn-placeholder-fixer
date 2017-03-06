#!/usr/bin/python

import koji
from hub import kojihub
import sys
import os
import threading
import Queue
from koji.context import context
import psycopg2
import urllib2
import commands
import shutil
import re


def get_archives(cur):
    cur.execute("""SELECT ai.build_id, p.id AS package_id, p.name AS package, b.version AS build_version, b.release as build_release, b.state, v.name AS volume_name, ai.filename, at.name AS archive_type, at.extensions, ma.archive_id, ma.group_id, ma.artifact_id, ma.version
    FROM archiveinfo ai
    LEFT JOIN build b ON b.id = ai.build_id
    LEFT JOIN package p ON b.pkg_id = p.id
    LEFT JOIN volume v ON b.volume_id = v.id
    LEFT JOIN maven_archives ma ON ma.archive_id = ai.id
    LEFT JOIN archivetypes at ON ai.type_id = at.id
    WHERE ma.version LIKE '%%${%%' or ma.group_id LIKE '%%${%%' or ma.artifact_id LIKE '%%${%%'""")
    rows = cur.fetchall()
    return [dict(zip(('build_id', 'package_id', 'package', 'build_version', 'build_release', 'state', 'volume_name', 'filename', 'archive_type', 'extensions', 'archive_id', 'group_id', 'artifact_id', 'version'), row)) for row in rows]


def get_builds(cur):
    cur.execute("""SELECT b.id AS build_id, p.id AS package_id, p.name AS package, b.version AS build_version, b.release as build_release, b.state, v.name AS volume_name, mb.group_id, mb.artifact_id, mb.version
    FROM build b
    LEFT JOIN maven_builds mb ON mb.build_id = b.id
    LEFT JOIN package p ON p.id = b.pkg_id
    LEFT JOIN volume v ON b.volume_id = v.id
    WHERE mb.version LIKE '%%${%%' or mb.group_id LIKE '%%${%%' or mb.artifact_id LIKE '%%${%%'""")
    rows = cur.fetchall()
    return [dict(zip(('build_id', 'package_id', 'package', 'build_version','build_release',  'state', 'volume_name', 'group_id', 'artifact_id', 'version'), row)) for row in rows]


def merge_data(archives, builds):
    results = {}
    former_result = {'build_id': -1, 'archives': []}
    for archive in archives:
        if former_result['build_id'] != archive['build_id']:
            former_result = dict((k, v) for k, v in archive.iteritems() if k in ['build_id', 'package_id', 'package', 'build_version', 'build_release', 'state', 'volume_name'])
            former_result['archives'] = []
            results[former_result['build_id']] = former_result
        former_result['archives'].append(dict((k, v) for k, v in archive.iteritems() if k in ['archive_id', 'filename', 'archive_type', 'extensions', 'group_id', 'artifact_id', 'version']))
    for build in builds:
        if build['build_id'] not in results:
            results[build['build_id']] = dict((k, v) for k, v in build.iteritems() if k in ['build_id', 'package_id', 'package', 'build_version', 'build_release', 'state', 'volume_name'])
        results[build['build_id']]['maven_build'] = dict((k, v) for k, v in build.iteritems() if k in ['group_id', 'artifact_id', 'version'])
        return results


def parse(build, cache, remote=False):
    buildinfo = get_buildinfo(build)
    buildpath = koji.pathinfo.mavenbuild(buildinfo)
    build['buildpath'] = buildpath
    if 'archives' in build:
        # for archive
        archives = build['archives']
        # skip deleted ones
        if build['state'] != 2:
            # firstly for pom files
            for archive in archives:
                (oripath, filepath, key, mavenpath) = get_pathinfo(buildinfo, archive, buildpath, remote)
                # store maven path
                archive['mavenpath'] = mavenpath
                if archive['archive_type'] == 'pom':
                    if remote:
                        try:
                            download_pomfile(oripath, filepath)
                        except Exception, e:
                            print 'Downloading file: "%s" to "%s" failed...' % (oripath, filepath) 
                            continue
                    for k, v in archive.copy().iteritems():
                        if k in ['group_id', 'artifact_id', 'version']:
                            if '${' in v and '}' in v:
                                m = re.match('^(.*)\$\{(.+)\}(.*)$', v)
                                if m:
                                    prefix = m.group(1)
                                    suffix = m.group(3)
                                    placeholder = m.group(2)
                                else:
                                    print '%s: "%s"is bad for archive:\n%r' % (k, v, archive)
                                    continue
                                if not placeholder:
                                    print 'Can not get placeholder in (%s,%s) for archive:\n%r' % (k, v, archive)
                                    continue
                                val = get_placeholder_value(placeholder, filepath)
                                if val:
                                    val = prefix + val + suffix
                                else:
                                    print 'Can not get val for placeholder: \'%s\' in pomfile: \'%s\'' % (placeholder, filepath)
                                    # TODO can get the val from filename or package.name and build.version
                                    continue
                                # set 'new_{key}' in archive
                                archive['new_' + k] = val
                                # update cache
                                cacheitem = {k: (v, val)}
                                if key not in cache:
                                    cache[key] = {}
                                    # also put it in cache by key = 'bid|filename_without_suffix'
                                    file_key = '%s|%s' % (build['build_id'], archive['filename'][:-4])
                                    cache[file_key] = cache[key]
                                # put it in cache by key = 'bid|g|a|v'
                                cache[key].update(cacheitem)
                            elif '$' in v:
                                print '%s: "%s"is bad for archive:\n%r' % (k, v, archive)
                    new_mavenpath = gen_mavenpath(archive, True)
                    if new_mavenpath != mavenpath:
                        archive['new_mavenpath'] = new_mavenpath
            
            # second, for other files
            for archive in archives:
                (oripath, filepath, key, mavenpath) = get_pathinfo(buildinfo, archive, buildpath, remote)
                if archive['archive_type'] != 'pom':
                    # get from cache by key = 'bid|g|a|v'
                    cacheitems = cache.get(key, None)
                    if not cacheitems:
                        # get from cache by key = 'bid|filename_without_suffix'
                        fn = archive['filename']
                        # firstly, check if filename is the same as pomfile
                        exts = archive['extensions'].split()
                        shortname = fn
                        for ext in exts:
                            if fn[-len(ext) - 1:] == ext:
                                shortname = fn[:-len(ext) - 1]
                                key = '%s|%s' % (build['build_id'], shortname)
                                cacheitems = cache.get(key, None)

                                break
                        # secondly, remove '-*' step by step to get cache
                        if not cacheitems:
                            parts = shortname.split('-')
                            for i in range(len(parts) - 1, -1, -1):
                                npart = '-'.join(parts[:i])
                                key = '%s|%s' % (build['build_id'], npart)
                                cacheitems = cache.get(key, None)
                    # set 'new_{key}' in archive
                    if cacheitems:
                        for k, (old, new) in cacheitems.iteritems():
                            if archive[k] == old:
                                archive['new_' + k] = new
                        new_mavenpath = gen_mavenpath(archive, True)
                        if new_mavenpath != mavenpath:
                            archive['new_mavenpath'] = new_mavenpath
                    else:
                        print 'Can not get the relative pomfile for archive:\n%r' % archive
        else:
            print 'build#%d has been deleted...' % buildinfo['id']

    # for maven_build and build.version
    # get the values from cache
    if 'maven_build' in build:
        maven_build = build['maven_build']
        key = str(buildinfo['id']) + ('/%(group_id)s/%(artifact_id)s/%(version)s' % maven_build)
        cacheitems = cache.get(key, None)
        if cacheitems:
            # update maven_build
            for k, (old, new) in cacheitems.iteritems():
                if maven_build[k] == old:
                    maven_build['new_' + k] = new
            # update build.version
            version = build['build_version']
            if version[:2] == '${' and version[-1:] == '}':
                (old, new) = cacheitems['version']
                if old == version:
                    build['new_build_version'] = new
                    new_buildpath = koji.pathinfo.build(get_buildinfo(build, True))
                    if new_buildpath != buildpath:
                        build['new_buildpath'] = new_buildpath
            # TODO maybe require to check package.name
        else:
            print 'Can not get the relative pomfile for maven_build:\n%r' % maven_build


def get_pathinfo(buildinfo, archive, buildpath, remote):
    repopath = koji.pathinfo.mavenrepo(archive)
    oripath = os.path.join(buildpath, repopath, archive['filename'])
    if remote:
        filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), ("vol/%(volume_name)s/packages/%(name)s/%(version)s/%(release)s" % buildinfo), 'maven', repopath, archive['filename'])
    else:
        filepath = oripath
    key = str(buildinfo['id']) + ('/%(group_id)s/%(artifact_id)s/%(version)s' % archive)
    return (oripath, filepath, key, repopath)


def download_pomfile(url, filepath):
    basedir = os.path.dirname(filepath)
    if not os.path.exists(basedir):
        os.makedirs(basedir)
    if not os.path.exists(filepath):
        print 'Begin to download file: %s' % url
        src = urllib2.urlopen(url, timeout=15)
        with open(filepath, 'wb') as f:
            f.write(src.read())
        src.close()
        print 'Downloading success, save to %s' % filepath
    else:
        print "file: %s already exists, skip it..." % filepath


def gen_mavenpath(archive, new=False):
    if new:
        archiveinfo = archive.copy()
        for k, v in archive.iteritems():
            if len(k) > 4 and k[:4] == 'new_':
                archiveinfo[k[4:]] = v
    else:
        archiveinfo = archive
    return koji.pathinfo.mavenrepo(archiveinfo)


def get_buildinfo(build, new=False):
    buildinfo = {}
    buildinfo['volume_name'] = build['volume_name']
    buildinfo['id'] = build['build_id']
    buildinfo['name'] = build['package']
    if new and 'new_build_version' in build:
        buildinfo['version'] = build['new_build_version']
    else:
        buildinfo['version'] = build['build_version']
    buildinfo['release'] = build['build_release']
    return buildinfo


def get_placeholder_value(placeholder, pomfile):
    if placeholder == 'parent.version':
        placeholder = 'project.parent.version'
    cmd = 'mvn org.apache.maven.plugins:maven-help-plugin:2.1.1:evaluate -Dexpression=\'%s\' -f \'%s\' | tail -8 | head -1' % (placeholder, pomfile)
    print 'Begin to execute cmd: %s' % cmd
    status, output = commands.getstatusoutput(cmd)
    if not status and '[ERROR]' not in output and ' ' not in output:
        print 'value of placeholder: %s is %s' % (placeholder, output)
        return output
    else:
        print 'maven output: \'%s\' is not expected, command is: \'%s\'' % (output, cmd)


def collect_changes(data):
    changes = []
    for id, d in data.iteritems():
        item = {}
        c = gen_change_item(d)
        if c:
            item['build'] = c
        if 'maven_build' in d:
            c = gen_change_item(d['maven_build'])
            if c:
                item['maven_build'] = c
        if 'archives' in d:
            al = []
            for archive in d['archives']:
                c = gen_change_item(archive)
                if c:
                    al.append((archive['archive_id'], c))
            if al:
                item['archives'] = al
        if item:
            item['build_id'] = id
            changes.append(item)
    return changes


def gen_change_item(d):
    item = []
    for k, v in d.iteritems():
        if len(k) > 4 and k[:4] == 'new_':
            item.append((k[4:], d[k[4:]], v))
    if item:
        return item


def gen_sql(table, id, changes, fields=None, id_field='id'):
    sets = []
    for field, old, new in changes:
        if field in ['buildpath', 'mavenpath']:
            continue
        if old != new:
            if fields and field in fields:
                field = fields[field]
            sets.append('%s = \'%s\'' % (field, new))
    if sets:
        return 'UPDATE %s SET %s WHERE %s=%d' % (table, ', '.join(sets), id_field, id)


def gen_sqls(changedata):
    sqls = []
    for data in changedata:
        build_id = data['build_id']
        if 'build' in data:
            sqls.append(gen_sql('build', build_id, data['build'], {'build_version': 'version'}))
        if 'maven_build' in data:
            sqls.append(gen_sql('maven_builds', build_id, data['maven_build'], id_field='build_id'))
        if 'archives' in data:
            for k, c in data['archives']:
                sqls.append(gen_sql('maven_archives', k, c, id_field='archive_id'))
    return sqls


def link_file(src, des):
    # TODO move or symbollink
    pass

def link_files(changes):
    # TODO
    pass


def main():
    try:
        conn = psycopg2.connect("dbname='koji' user='koji'")
    except Exception:
        print 'Can not connect to db'
        raise
    cur = conn.cursor()
    remote = True
    if remote:
        koji.pathinfo.topdir = 'https://brewweb.engineering.redhat.com/brewroot/'
    maven_archives = get_archives(cur)
    maven_builds = get_builds(cur)
    data = merge_data(maven_archives, maven_builds)
    cache = {}
    for d in data.itervalues():
        parse(d, cache, remote)
    changes = collect_changes(data)
    print changes
    sqls = gen_sqls(changes)
    print sqls



if __name__ == '__main__':
    main ()