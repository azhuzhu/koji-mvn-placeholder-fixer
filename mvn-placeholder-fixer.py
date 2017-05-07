#!/usr/bin/python
# coding=utf-8

import imp
from optparse import OptionParser
import koji
from hub import kojihub
import sys
import os
from koji.context import context
import psycopg2
import urllib2
import commands
import re
from sets import Set

# a bit of a hack to import the koji cli code
fo = file('/usr/bin/koji', 'U')
try:
    clikoji = imp.load_module('clikoji', fo, fo.name, ('.py', 'U', 1))
finally:
    fo.close()
# hack up fake options for benefit of watch_tasks()
class fakeopts(object):
    pass
global options
options = fakeopts()
clikoji.options = options
options.poll_interval = 5


def get_opts():
    """process command line arguments"""
    usage = """
Fix the dirty data caused by wrong maven placeholder parsing.
Will update GAV in maven_archives and maven_builds, and version in build table,
and also symlink the archive files on volumes, then regenerate repos by default.
%prog [options]"""
    parser = OptionParser(usage=usage)
    parser.add_option(
        '-d',
        '--dryrun',
        action='store_true',
        default=False,
        help='Don\'t really execute any update and file operation')
    parser.add_option(
        '-r',
        '--remote',
        action='store_true',
        default=False,
        help='Would be specified when remote running, will copy files to current dictionary')
    parser.add_option('-H', '--dbhost', default='localhost',
                      help='Specify DB host')
    parser.add_option('-P', '--dbport', default='5432', help='Specify DB port')
    parser.add_option('-U', '--dbname', default='koji', help='Specify DB name')
    parser.add_option(
        '-u',
        '--user',
        default='koji',
        help='Specify DB username')
    parser.add_option('-p', '--password', help='Specify DB user password')
    parser.add_option('-s', '--ssl', action='store_true', default=False,
                      help='Whether login by ssl, otherwise by kerberos')
    parser.add_option('--cert', default='~/.koji/client.pem',
                      help='Specify client cert file for ssl login')
    parser.add_option(
        '--serverca',
        default='~/.koji/serverca.crt',
        help='Specify serverca for ssl login')
    parser.add_option('-T', '--topdir', default='/mnt/koji',
                      help='Specify topdir when local running')
    parser.add_option(
        '-t',
        '--topurl',
        default='https://brewweb.engineering.redhat.com/brewroot',
        help='Specify topurl when remote running')
    parser.add_option(
        '-k',
        '--huburl',
        default='https://localhost/kojihub',
        help='Specify spec hub xmlrpc url for regenerating repos')
    parser.add_option(
        '-e',
        '--export',
        action='store_true',
        default=False,
        help='If exporting sql, symlink and regen-repo commands. If True, will skip the execution')
    parser.add_option(
        '-R',
        '--regen-repo',
        help='Only regenerate repos for the tags in specified files')
    opts, args = parser.parse_args()
    return args, opts


def get_archives(cur):
    cur.execute(
        """SELECT ai.build_id, p.id AS package_id, p.name AS package, b.version AS build_version, b.release as build_release, b.state, v.name AS volume_name, ai.filename, at.name AS archive_type, at.extensions, ma.archive_id, ma.group_id, ma.artifact_id, ma.version
    FROM archiveinfo ai
    LEFT JOIN build b ON b.id = ai.build_id
    LEFT JOIN package p ON b.pkg_id = p.id
    LEFT JOIN volume v ON b.volume_id = v.id
    LEFT JOIN maven_archives ma ON ma.archive_id = ai.id
    LEFT JOIN archivetypes at ON ai.type_id = at.id
    WHERE ma.version LIKE '%%${%%' or ma.group_id LIKE '%%${%%' or ma.artifact_id LIKE '%%${%%'""")
    rows = cur.fetchall()
    return [dict(zip(('build_id',
                      'package_id',
                      'package',
                      'build_version',
                      'build_release',
                      'state',
                      'volume_name',
                      'filename',
                      'archive_type',
                      'extensions',
                      'archive_id',
                      'group_id',
                      'artifact_id',
                      'version'),
                     row)) for row in rows]


def get_builds(cur):
    cur.execute(
        """SELECT b.id AS build_id, p.id AS package_id, p.name AS package, b.version AS build_version, b.release as build_release, b.state, v.name AS volume_name, mb.group_id, mb.artifact_id, mb.version
    FROM build b
    LEFT JOIN maven_builds mb ON mb.build_id = b.id
    LEFT JOIN package p ON p.id = b.pkg_id
    LEFT JOIN volume v ON b.volume_id = v.id
    WHERE mb.version LIKE '%%${%%' or mb.group_id LIKE '%%${%%' or mb.artifact_id LIKE '%%${%%'""")
    rows = cur.fetchall()
    return [dict(zip(('build_id',
                      'package_id',
                      'package',
                      'build_version',
                      'build_release',
                      'state',
                      'volume_name',
                      'group_id',
                      'artifact_id',
                      'version'),
                     row)) for row in rows]


def merge_data(archives, builds):
    results = {}
    former_result = {'build_id': -1, 'archives': []}
    for archive in archives:
        if former_result['build_id'] != archive['build_id']:
            former_result = dict(
                (k,
                 v) for k,
                v in archive.iteritems() if k in [
                    'build_id',
                    'package_id',
                    'package',
                    'build_version',
                    'build_release',
                    'state',
                    'volume_name'])
            former_result['archives'] = []
            results[former_result['build_id']] = former_result
        former_result['archives'].append(
            dict(
                (k,
                 v) for k,
                v in archive.iteritems() if k in [
                    'archive_id',
                    'filename',
                    'archive_type',
                    'extensions',
                    'group_id',
                    'artifact_id',
                    'version']))
    for build in builds:
        if build['build_id'] not in results:
            results[
                build['build_id']] = dict(
                (k,
                 v) for k,
                v in build.iteritems() if k in [
                    'build_id',
                    'package_id',
                    'package',
                    'build_version',
                    'build_release',
                    'state',
                    'volume_name'])
        results[
            build['build_id']]['maven_build'] = dict(
            (k, v) for k, v in build.iteritems() if k in [
                'group_id', 'artifact_id', 'version'])
        return results


def parse(build, cache, remote=False):
    buildinfo = get_buildinfo(build)
    buildpath = koji.pathinfo.mavenbuild(buildinfo)
    if remote:
        build['buildpath'] = os.path.join(
            os.path.dirname(
                os.path.abspath(__file__)),
            ("vol/%(volume_name)s/packages/%(name)s/%(version)s/%(release)s" %
             buildinfo),
            'maven')

    else:
        build['buildpath'] = buildpath
    if 'archives' in build:
        # for archive
        archives = build['archives']
        # skip deleted ones
        if build['state'] != 2:
            # firstly for pom files
            for archive in archives:
                (oripath, filepath, key, mavenpath) = get_pathinfo(
                    buildinfo, archive, buildpath, remote)
                # store maven path
                archive['mavenpath'] = mavenpath
                if archive['archive_type'] == 'pom':
                    if remote:
                        try:
                            download_file(oripath, filepath)
                        except Exception as e:
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
                                val = get_placeholder_value(
                                    placeholder, filepath)
                                if val:
                                    val = prefix + val + suffix
                                else:
                                    print 'Can not get val for placeholder: \'%s\' in pomfile: \'%s\'' % (placeholder, filepath)
                                    # TODO can get the val from filename or
                                    # package.name and build.version
                                    continue
                                # set 'new_{key}' in archive
                                archive['new_' + k] = val
                                # update cache
                                cacheitem = {k: (v, val)}
                                if key not in cache:
                                    cache[key] = {}
                                    # also put it in cache by key =
                                    # 'bid|filename_without_suffix'
                                    file_key = '%s|%s' % (
                                        build['build_id'], archive['filename'][:-4])
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
                (oripath, filepath, key, mavenpath) = get_pathinfo(
                    buildinfo, archive, buildpath, remote)
                if archive['archive_type'] != 'pom':
                    if remote:
                        try:
                            download_file(oripath, filepath)
                        except Exception as e:
                            print 'Downloading file: "%s" to "%s" failed...' % (oripath, filepath)
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
        key = str(
            buildinfo['id']) + ('/%(group_id)s/%(artifact_id)s/%(version)s' % maven_build)
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
                    new_buildpath = koji.pathinfo.build(
                        get_buildinfo(build, True))
                    if new_buildpath != buildpath:
                        build['new_buildpath'] = new_buildpath
            # TODO maybe require to check package.name
        else:
            print 'Can not get the relative pomfile for maven_build:\n%r' % maven_build


def get_pathinfo(buildinfo, archive, buildpath, remote):
    repopath = koji.pathinfo.mavenrepo(archive)
    oripath = os.path.join(buildpath, repopath, archive['filename'])
    if remote:
        filepath = os.path.join(
            os.path.dirname(
                os.path.abspath(__file__)),
            ("vol/%(volume_name)s/packages/%(name)s/%(version)s/%(release)s" %
             buildinfo),
            'maven',
            repopath,
            archive['filename'])
    else:
        filepath = oripath
    key = str(buildinfo['id']) + \
        ('/%(group_id)s/%(artifact_id)s/%(version)s' % archive)
    return (oripath, filepath, key, repopath + '/' + archive['filename'])


def download_file(url, filepath):
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
    return koji.pathinfo.mavenrepo(archiveinfo) + '/' + archive['filename']


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
    cmd = 'mvn org.apache.maven.plugins:maven-help-plugin:2.1.1:evaluate -Dexpression=\'%s\' -f \'%s\' | tail -8 | head -1' % (
        placeholder, pomfile)
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
            item['buildpath'] = d['buildpath']
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
        return 'UPDATE %s SET %s WHERE %s=%d' % (
            table, ', '.join(sets), id_field, id)


def gen_sqls(changedata):
    sqls = []
    for data in changedata:
        build_id = data['build_id']
        if 'build' in data:
            sqls.append(
                gen_sql(
                    'build', build_id, data['build'], {
                        'build_version': 'version'}))
        if 'maven_build' in data:
            sqls.append(
                gen_sql(
                    'maven_builds',
                    build_id,
                    data['maven_build'],
                    id_field='build_id'))
        if 'archives' in data:
            for k, c in data['archives']:
                sqls.append(
                    gen_sql(
                        'maven_archives',
                        k,
                        c,
                        id_field='archive_id'))
    return sqls


def export_sql(sqls, filepath):
    with open(filepath, 'wb') as f:
        for sql in sqls:
            f.write(sql + ";\n")


def run_sqls(cur, sqls):
    for sql in sqls:
        try:
            cur.execute(sql)
        except Exception as e:
            print 'fail to run SQL:\n\'%s\'\n%s' % (sql, e.arg[0])


def link_file(src, des, dryrun=False):
    if not os.path.exists(src):
        return 'SRC_NOT_EXISTS'
    if os.path.exists(des):
        return 'DES_EXISTS'
    basedir = os.path.dirname(des)
    if dryrun:
        return 'DRYRUN'
    try:
        if not os.path.exists(basedir):
            os.makedirs(basedir)
        os.symlink(os.path.relpath(src, des), des)
        if os.path.exists(os.path.abspath(src + '.sha1')):
            os.symlink(os.path.abspath(src + '.sha1'), des + '.sha1')
        if os.path.exists(os.path.abspath(src + '.md5')):
            os.symlink(os.path.abspath(src + '.md5'), des + '.md5')
        kojihub._generate_maven_metadata(os.path.dirname(des))
        return 'SUCCESS'
    except Exception as e:
        print e
    return 'FAILED'


def link_files(changes, dryrun=False):
    result = []
    for change in changes:
        build_id = change['build_id']
        buildpath = change['buildpath']
        new_buildpath = change.get('new_buildpath', buildpath)
        if 'archives' in change:
            for archive in change['archives']:
                for c in archive[1]:
                    if c[0] == 'mavenpath':
                        mavenpath = c[1]
                        new_mavenpath = c[2]
                        if mavenpath and new_mavenpath:
                            srcpath = os.path.join(buildpath, mavenpath)
                            despath = os.path.join(
                                new_buildpath, new_mavenpath)
                        if srcpath != despath:
                            result.append(
                                [link_file(srcpath, despath, dryrun), build_id, srcpath, despath])
                        else:
                            result.append(
                                ['SKIP_SAME', build_id, srcpath, despath])
    return result


def gen_link_cmds(link_result, filepath):
    with open(filepath, 'wb') as f:
        f.write('#!/bin/bash\n\n')
        for r in link_result:
            f.write('# build#%d, expect %s\n' % (r[1], r[0]))
            if r[0] not in ['SUCCESS', 'DRYRUN']:
                f.write('# ')
            f.write('ln -s \'%s\' \'%s\'\n\n' %
                    (os.path.relpath(r[2], r[3]), r[3]))


def get_tags(session, changes):
    tags = Set()
    for change in changes:
        taginfos = session.listTags(change['build_id'])
        for taginfo in taginfos:
            tags.add(str(taginfo['id']))
    return tags


def regen_repo(session, tag_id):
    repo_info = session.getRepo(tag_id, strict=True)
    if koji.REPO_STATES[repo_info['state']] in ['READY', 'EXPIRED']:
        print "Duplicating repo"
        rtaskid = session.newRepo(tag_id)
        clikoji.watch_tasks(session, [rtaskid])
        new_repo_id, event_id = session.getTaskResult(rtaskid)
    return new_repo_id


def regen_repos(session, tags):
    for tag_id in tags:
        try:
            new_repo_id = regen_repo(session, tag_id)
            print "regenerate repo for tag#%s -> new_repo#%s" % (tag_id, new_repo_id)
        except Exception:
            print "fail to regen repo for tag#%s" % tag_id


def export_tags(tags, filepath):
    with open(filepath, 'wb') as f:
        f.write('\n'.join(tags))


def get_session(options):
    if options.ssl:
        cert = os.path.abspath(os.path.expanduser(options.cert))
        serverca = os.path.abspath(os.path.expanduser(options.serverca))
        print 'Connecting to \'%s\'' % options.huburl
        print 'cert: %s\nserverca:%s' % (cert, serverca)
        session = koji.ClientSession(options.huburl, {'anon_retry': True})
        session.ssl_login(
            cert=os.path.abspath(
                os.path.expanduser(
                    options.cert)), serverca=os.path.abspath(
                os.path.expanduser(
                    options.serverca)))
    else:
        session = koji.ClientSession(
            options.huburl, {
                'anon_retry': True, 'krbservice': 'brewhub'})
    #session = koji.ClientSession('http://brewhub.engineering.redhat.com/kojihub', {'anon_retry':True})
    #session = koji.ClientSession('http://brew-test.devel.redhat.com/kojihub', {'anon_retry':True})
    #session = koji.ClientSession('http://brewhub.devel.redhat.com/brewhub', {'anon_retry':True})
        session.krb_login()
    return session


def main():
    args, options = get_opts()
    if options.regen_repo:
        session = get_session(options)
        tags = []
        with open(options.regen_repo, 'r') as f:
            for line in f:
                if line:
                    tags.append(line[:-1])
        regen_repos(session, tags)

    dryrun = options.dryrun
    remote = options.remote
    export = options.export
    dbopts = {'host': options.dbhost,
              'port': options.dbport,
              'dbname': options.dbname,
              'user': options.user,
              }
    if options.password:
        dbopts['password']: options.password
    try:
        conn = psycopg2.connect(**dbopts)
    except Exception:
        print 'Can not connect to db'
        raise
    cur = conn.cursor()
    cur.execute('BEGIN')
    if remote:
        koji.pathinfo.topdir = options.topurl
    else:
        koji.pathinfo.topdir = options.topdir
    maven_archives = get_archives(cur)
    maven_builds = get_builds(cur)
    data = merge_data(maven_archives, maven_builds)
    cache = {}
    for d in data.itervalues():
        parse(d, cache, remote)
    changes = collect_changes(data)
    print 'Changes:\n%s' % changes
    sqls = gen_sqls(changes)
    print 'Update SQLs:\n%s' % sqls
    if export:
        export_sql(sqls, 'updates.sql')
    if not dryrun and not export:
        run_sqls(cur, sqls)
    cur.execute('COMMIT')

    link_result = link_files(changes, dryrun or export)
    print 'Symbol Link Result:\n%s' % link_result
    if export:
        gen_link_cmds(link_result, 'link_files.sh')

    session = get_session(options)

    tags = get_tags(session, changes)
    print "those tags' repos will be re-generated: %s" % tags
    if not dryrun and not export:
        regen_repos(session, tags)
    if export:
        export_tags(tags, 'tag-list.txt')


if __name__ == '__main__':
    main()
