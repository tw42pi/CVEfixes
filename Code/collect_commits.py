import ast
import os
import re
import uuid
from random import sample

import pandas as pd
import requests
from bs4 import BeautifulSoup

import configuration as cf
from guesslang import Guess
from pydriller import Repository
from utils import log_commit_urls

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

fixes_columns = [
    'cve_id',
    'hash',
    'repo_url',
]

commit_columns = [
    'hash',
    'repo_url',
    'author',
    'author_date',
    'author_timezone',
    'committer',
    'committer_date',
    'committer_timezone',
    'msg',
    'merge',
    'parents',
    'num_lines_added',
    'num_lines_deleted',
    'dmm_unit_complexity',
    'dmm_unit_interfacing',
    'dmm_unit_size'
]

file_columns = [
    'file_change_id',
    'hash',
    'filename',
    'old_path',
    'new_path',
    'change_type',
    'diff',
    'diff_parsed',
    'num_lines_added',
    'num_lines_deleted',
    'code_after',
    'code_before',
    'nloc',
    'complexity',
    'token_count',
    'programming_language'
]

method_columns = [
    'method_change_id',
    'file_change_id',
    'name',
    'signature',
    'parameters',
    'start_line',
    'end_line',
    'code',
    'nloc',
    'complexity',
    'token_count',
    'top_nesting_level',
    'before_change',
]

commit_url_old = re.compile(r'(((?P<repo>(https|http):\/\/(bitbucket|github|gitlab)\.(org|com)\/(?P<owner>[^\/]+)\/' \
                            r'(?P<project>[^\/]*))\/(commit|commits)\/(?P<hash>\w+)#?)+)')
commit_url_git_svm = re.compile(r'(?P<repo>(https|http):\/\/(?P<domain>[^\/]+)(?P<subdirs>(\/[^\/]+)*))\/?' \
                                r'\?(p=(?P<project>[^;]+);)?a=commit(diff(_plain)?)?;h=(?P<hash>[a-f0-9]{6,40})#?')
commit_url_cgit = re.compile(r'(?P<repo>(https|http):\/\/(?P<domain>[^\/]+)(?P<subdirs>(\/[^\/]+)*))\/commit\/?' \
                             r'\?(h=(?P<project>[^&]+)&)?id=(?P<hash>[a-f0-9]{6,40})#?')
commit_url = re.compile(r'(?P<repo>(https|http):\/\/(?P<domain>[^\/]+)(?P<subdirs>(\/[^\/]+)*))(\/-)?\/' \
                        r'(commit|commits|\+)\/(\?id=)?(?P<hash>[a-f0-9]{6,40})#?')
pullrequest_url = re.compile(r'(((?P<repo>(https|http):\/\/(bitbucket|github|gitlab)\.(org|com)\/(?P<owner>[^\/]+)\/' \
                             r'(?P<project>[^\/]*))\/pull\/(?P<ID>\w+)#?)+)')
issue_url = re.compile(r'(((?P<repo>(https|http):\/\/(bitbucket|github|gitlab)\.(org|com)\/(?P<owner>[^\/]+)\/' \
                       r'(?P<project>[^\/]*))\/issues\/(?P<ID>\w+)#?)+)')
url_map = {}


def extract_repo_url_svm(url):
    request = requests.get(url)
    web_data = request.content
    soup = BeautifulSoup(web_data, features="html.parser")
    possible_repo_urls = soup.select(".metadata_url > td")
    # print(url, possible_repo_urls)
    for v in ["http", "git", "ssh"]:
        for repo_url in possible_repo_urls:
            if repo_url.string and repo_url.string.startswith(v):
                return repo_url.string
#    print("nothing found for ", url)


def extract_repo_url_cgit(url):
    request = requests.get(url)
    web_data = request.content
    soup = BeautifulSoup(web_data, features="html.parser")
    possible_repo_urls = soup.select('a[rel="vcs-git"]')
    # print(url, possible_repo_urls)
    for v in ["http", "git", "ssh"]:
        for a in possible_repo_urls:
            repo_url = a["href"]
            if repo_url and repo_url.startswith(v):
                return repo_url
#    print("nothing found for ", url)


def check_url_commit(url):
    link = commit_url.search(url)
    if link:
        return [link.group('hash')], link.group('repo').replace(r'http:', r'https:')
    return [], None


def check_url_commit_git_svm(url):
    url = url.replace("%3B", ";")
    link = commit_url_git_svm.search(url)
    if link:
        matching_part = url[:url.find("a=commit")]
        if matching_part in url_map:
            repo_url = url_map[matching_part]
            if repo_url:
                return [link.group('hash')], repo_url
            return [], "dead"
        try:
            url = requests.head(url.replace("diff_plain", "diff"), allow_redirects=True).url
            redirect = commit_url_git_svm.search(url)
            if redirect:
                repo_url = extract_repo_url_svm(matching_part)
                url_map[matching_part] = repo_url
                # print("mapping", matching_part, " -> ", repo_url)
                if repo_url:
                    return [link.group('hash')], repo_url
                return [], "dead"
            # redirected url might be detectable
            return check_url_commit(url)
        except requests.exceptions.ConnectionError:
            url_map[matching_part] = None
            return [], "dead"
        except Exception as e:
            print("Something went wrong with ", url, e)
    return [], None


def check_url_commit_cgit(url):
    link = commit_url_cgit.search(url)
    if link:
        matching_part = link.group("repo")
        if matching_part in url_map:
            repo_url = url_map[matching_part]
            if repo_url:
                return [link.group('hash')], repo_url
            return [], "dead"
        try:
            url = requests.head(url, allow_redirects=True).url
            redirect = commit_url_cgit.search(url)
            if redirect:
                repo_url = extract_repo_url_cgit(matching_part)
                url_map[matching_part] = repo_url
                # print("mapping", matching_part, " -> ", repo_url)
                if repo_url:
                    return [link.group('hash')], repo_url
                return [], "dead"
            # redirected url might be detectable
            return check_url_commit(url)
        except requests.exceptions.ConnectionError:
            url_map[matching_part] = None
            return [], "dead"
        except Exception as e:
            print("Something went wrong with ", url, e)
    return [], None


def check_url_pullrequest(url):
    link = pullrequest_url.search(url)
    if link:
        commit_list_url = link.group('repo') + "/pull/" + link.group('ID') + "/commits_list"
        # header = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"}
        # print("PR ", url, commit_list_url)
        request = requests.get(commit_list_url)
        if request.request.url != commit_list_url:
            print(commit_list_url, "->", request.request.url)
            if request.request.url.endswith("issues/" + link.group('ID')):
                return [], "processed"
        web_data = request.content
        soup = BeautifulSoup(web_data, features="html.parser")
        # print(url, commit_list_url)
        # print(soup)

        # print(link.group('repo'))
        # print(soup.find_all("clipboard-copy"))
        try:
            hashes = [item["value"] for item in
                      soup.find_all("clipboard-copy")]  # if "value" in item]  # soup.select("input[name='oid']")]
        # for item in soup.find_all("clipboard-copy"):
        #    if not "value" in item:
        except KeyError:
            cf.logger.debug(f"weird behaviour at {url} with {soup.find_all('clipboard-copy')}")

        # print(hashes)
        # a = input("verify PR "+url)
        if hashes:
            return hashes, link.group('repo').replace(r'http:', r'https:')
        return [], "processed"
    return [], None


def check_url_issue(url):
    link = issue_url.search(url)
    if link:
        issues_url = link.group('repo') + "/issues/" + link.group('ID')
        # header = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"}
        # print("issue ", url, issues_url)
        request = requests.get(issues_url)
        web_data = request.content
        soup = BeautifulSoup(web_data, features="html.parser")
        search_string = f"/{link.group('owner')}/{link.group('project')}/commit/"
        # print(search_string)
        links = []
        for item in soup.select(f"a[href*='{search_string}']"):
            # print(item.get("class","noclass"), item)
            if "commit-tease-sha" not in item.get("class", []):
                href = item["href"]
                if not href.startswith(search_string):
                    href = href[href.find(search_string):]
                links.append(href)
        hashes = set([link.split("/")[4] for link in links])  # soup.select("input[name='oid']")]
        # print(hashes)
        search_string = f"/{link.group('owner')}/{link.group('project')}/pull/"
        # print(search_string)
        pullrequests = [item["href"] for item in soup.select(f"a[href*='{search_string}']")]
        for pullrequest in pullrequests:
            if pullrequest.startswith(search_string):
                pullrequest = "https://github.com" + pullrequest
            new_hashes, _ = check_url_pullrequest(pullrequest)
            # print(pullrequest, new_hashes)
            hashes |= set(new_hashes)
            # print(hashes)
        # a = input("verify "+url)
        if hashes:
            return list(hashes), link.group('repo').replace(r'http:', r'https:')
        return [], "processed"
    return [], None


def check_url(url):
    for func in [check_url_commit_git_svm, check_url_commit_cgit, check_url_commit, check_url_pullrequest, check_url_issue]:
        hashes, repo = func(url)
        if hashes:
            return hashes, repo
        if repo:
            return [], "processed"
    return [], None


def test_random_subset_cve_links(df_master):
    MAX_ENTRIES = -1
    not_found = 0
    num_found = 0
    num_processed = 0
    num_now_found = 0
    # print(len(df_master))
    # for i in sample(range(len(df_master)), len(df_master)):
    for i in range(len(df_master)):
        ref_list = ast.literal_eval(df_master['reference_json'].iloc[i])
        found = False
        new_found_url = []
        other_url = []
        processed_url = []
        if len(ref_list) > 0:
            for ref in ref_list:
                url = dict(ref)['url']
                link = commit_url_old.search(url)
                if link:
                    found = True
                else:
                    hashes, repo_url = check_url(url)
                    if hashes:
                        new_found_url.append(url)
                    elif repo_url == "processed":
                        processed_url.append(url)
                    else:
                        ignore_urls = ["redhat.com", "ubuntu.com", "debian.org", "opensuse.org", "exchange",
                                       "apache.org",
                                       ".xforce.ibmcloud.c", "exploit-db.c", "twitter.com", "securitytracker.com",
                                       "/advisories", "osvdb.org", "marc.info", "//lists.", "/securitybulletins",
                                       "securityfocus.com", "securityreason.com", "oracle.com", "cert.", "security.org"]
                        show_urls = ["git", "commit"]  # , "svn"]
                        # if not [item for item in ignore_urls if item in url]:
                        if [item for item in show_urls if item in url and not "igit" in url]:
                            other_url.append(url)
            if not found:
                if new_found_url:
                    num_now_found += 1
                    urls = "\n".join(new_found_url)
                    # cf.logger.debug(f'{df_master["cve_id"][i]}: now found urls:\n{urls}')
                elif processed_url:
                    num_processed += 1
                    urls = "\n".join(processed_url)
                    # cf.logger.debug(f'{df_master["cve_id"][i]}: now processed urls:\n{urls}')
                elif other_url:
                    urls = "\n".join(other_url)
                    cf.logger.debug(f'{df_master["cve_id"][i]}: ignored urls:\n{urls}')
                not_found += 1
                if not_found == MAX_ENTRIES:
                    break
            else:
                num_found += 1
    return num_found, num_now_found, num_processed


def extract_project_links(df_master):
    """
    extracts all the reference urls from CVE records that match to the repo commit urls
    """
    df_fixes = pd.DataFrame(columns=fixes_columns)
    cf.logger.info('-' * 70)
    cf.logger.info('Extracting all reference URLs from CVEs...')
    for i in range(len(df_master)):
        ref_list = ast.literal_eval(df_master['reference_json'].iloc[i])
        found = False
        other_url = []
        if len(ref_list) > 0:
            for ref in ref_list:
                hashes, repo_url = check_url(dict(ref)['url'])

                for commit_hash in hashes:
                    row = {
                        'cve_id': [df_master['cve_id'][i]],
                        'hash': [commit_hash],
                        'repo_url': [repo_url]
                    }
                    series = pd.DataFrame.from_dict(row)
                    df_fixes = pd.concat([df_fixes, series])
                    # cf.logger.debug(f'{df_master["cve_id"][i]}: ACCEPTED url "{url}"')
                    found = True
                if not hashes:
                    other_url.append(dict(ref)['url'])
            if not found and other_url:
                urls = "\n".join(other_url)
                cf.logger.debug(f'{df_master["cve_id"][i]}: ignored urls:\n{urls}')

    df_fixes = df_fixes.drop_duplicates().reset_index(drop=True)
    cf.logger.info(f'Found {len(df_fixes)} references to vulnerability fixing commits')
    return df_fixes


def guess_pl(code):
    """
    :returns guessed programming language of the code
    """
    if code:
        return Guess().language_name(code.strip())
    else:
        return 'unknown'


def clean_string(signature):
    return signature.strip().replace(' ', '')


def get_method_code(source_code, start_line, end_line):
    try:
        if source_code is not None:
            code = ('\n'.join(source_code.split('\n')[int(start_line) - 1: int(end_line)]))
            return code
        else:
            return None
    except Exception as e:
        cf.logger.warning(f'Problem while extracting method code from the changed file contents: {e}')
        pass


def changed_methods_both(file):
    """
    Return the list of methods that were changed.
    :return: list of methods
    """
    new_methods = file.methods
    old_methods = file.methods_before
    added = file.diff_parsed["added"]
    deleted = file.diff_parsed["deleted"]

    methods_changed_new = {
        y
        for x in added
        for y in new_methods
        if y.start_line <= x[0] <= y.end_line
    }
    methods_changed_old = {
        y
        for x in deleted
        for y in old_methods
        if y.start_line <= x[0] <= y.end_line
    }
    return methods_changed_new, methods_changed_old


# --------------------------------------------------------------------------------------------------------
# extracting method_change data
def get_methods(file, file_change_id):
    """
    returns the list of methods in the file.
    """
    file_methods = []
    try:
        if file.changed_methods:
            cf.logger.debug('-' * 70)
            cf.logger.debug('methods_after: ')
            for m in file.methods:
                if m.name != '(anonymous)':
                    cf.logger.debug(m.long_name)

            cf.logger.debug('- ' * 35)
            cf.logger.debug('methods_before: ')
            for mb in file.methods_before:
                if mb.name != '(anonymous)':
                    cf.logger.debug(mb.long_name)

            cf.logger.debug('- ' * 35)
            cf.logger.debug('changed_methods: ')
            for mc in file.changed_methods:
                if mc.name != '(anonymous)':
                    cf.logger.debug(mc.long_name)
            cf.logger.debug('-' * 70)

            # for mb in file.methods_before:
            #     for mc in file.changed_methods:
            #         #if mc.name == mb.name and mc.name != '(anonymous)':
            #         if clean_string(mc.long_name) == clean_string(mb.long_name) and mc.name != '(anonymous)':

            if file.changed_methods:
                methods_after, methods_before = changed_methods_both(file)  # in source_code_after/_before
                if methods_before:
                    for mb in methods_before:
                        # filtering out code not existing, and (anonymous)
                        # because lizard API classifies the code part not as a correct function.
                        # Since, we did some manual test, (anonymous) function are not function code.
                        # They are also not listed in the changed functions.
                        if file.source_code_before is not None and mb.name != '(anonymous)':
                            method_before_code = get_method_code(file.source_code_before, mb.start_line, mb.end_line)
                            method_before_row = {
                                'method_change_id': uuid.uuid4().fields[-1],
                                'file_change_id': file_change_id,
                                'name': mb.name,
                                'signature': mb.long_name,
                                'parameters': mb.parameters,
                                'start_line': mb.start_line,
                                'end_line': mb.end_line,
                                'code': method_before_code,
                                'nloc': mb.nloc,
                                'complexity': mb.complexity,
                                'token_count': mb.token_count,
                                'top_nesting_level': mb.top_nesting_level,
                                'before_change': 'True',
                            }
                            file_methods.append(method_before_row)

                if methods_after:
                    for mc in methods_after:
                        if file.source_code is not None and mc.name != '(anonymous)':
                            # changed_method_code = ('\n'.join(file.source_code.split('\n')[int(mc.start_line) - 1: int(mc.end_line)]))
                            changed_method_code = get_method_code(file.source_code, mc.start_line, mc.end_line)
                            changed_method_row = {
                                'method_change_id': uuid.uuid4().fields[-1],
                                'file_change_id': file_change_id,
                                'name': mc.name,
                                'signature': mc.long_name,
                                'parameters': mc.parameters,
                                'start_line': mc.start_line,
                                'end_line': mc.end_line,
                                'code': changed_method_code,
                                'nloc': mc.nloc,
                                'complexity': mc.complexity,
                                'token_count': mc.token_count,
                                'top_nesting_level': mc.top_nesting_level,
                                'before_change': 'False',
                            }
                            file_methods.append(changed_method_row)

        if file_methods:
            return file_methods
        else:
            return None

    except Exception as e:
        cf.logger.warning(f'Problem while fetching the methods: {e}')
        pass


# ---------------------------------------------------------------------------------------------------------
# extracting file_change data of each commit
def get_files(commit):
    """
    returns the list of files of the commit.
    """
    commit_files = []
    commit_methods = []
    try:
        cf.logger.info(f'Extracting files for {commit.hash}')
        if commit.modified_files:
            for file in commit.modified_files:
                cf.logger.debug(f'Processing file {file.filename} in {commit.hash}')
                # programming_language = (file.filename.rsplit(".')[-1] if '.' in file.filename else None)
                programming_language = guess_pl(file.source_code)  # guessing the programming language of fixed code
                file_change_id = uuid.uuid4().fields[-1]

                file_row = {
                    'file_change_id': file_change_id,  # filename: primary key
                    'hash': commit.hash,  # hash: foreign key
                    'filename': file.filename,
                    'old_path': file.old_path,
                    'new_path': file.new_path,
                    'change_type': file.change_type,  # i.e. added, deleted, modified or renamed
                    'diff': file.diff,  # diff of the file as git presents it (e.g. @@xx.. @@)
                    'diff_parsed': file.diff_parsed,  # diff parsed in a dict containing added and deleted lines lines
                    'num_lines_added': file.added_lines,  # number of lines added
                    'num_lines_deleted': file.deleted_lines,  # number of lines removed
                    'code_after': file.source_code,
                    'code_before': file.source_code_before,
                    'nloc': file.nloc,
                    'complexity': file.complexity,
                    'token_count': file.token_count,
                    'programming_language': programming_language,
                }
                commit_files.append(file_row)
                file_methods = get_methods(file, file_change_id)

                if file_methods is not None:
                    commit_methods.extend(file_methods)
        else:
            cf.logger.info('The list of modified_files is empty')

        return commit_files, commit_methods

    except Exception as e:
        cf.logger.warning(f'Problem while fetching the files: {e}')
        pass


def extract_commits(repo_url, hashes):
    """This function extract git commit information of only the hashes list that were specified in the
    commit URL. All the commit_fields of the corresponding commit have been obtained.
    Every git commit hash can be associated with one or more modified/manipulated files.
    One vulnerability with same hash can be fixed in multiple files so we have created a dataset of modified files
    as 'df_file' of a project.
    :param repo_url: list of url links of all the projects.
    :param hashes: list of hashes of the commits to collect
    :return dataframes: at commit level and file level.
    """
    repo_commits = []
    repo_files = []
    repo_methods = []

    # ----------------------------------------------------------------------------------------------------------------
    # extracting commit-level data
    if 'github' in repo_url:
        repo_url = repo_url + '.git'

    cf.logger.debug(
        f'Extracting commits for {repo_url} with {cf.NUM_WORKERS} worker(s) looking for the following hashes:')
    log_commit_urls(repo_url, hashes)

    # giving first priority to 'single' parameter for single hash because
    # it has been tested that 'single' gets commit information in some cases where 'only_commits' does not,
    # for example: https://github.com/hedgedoc/hedgedoc.git/35b0d39a12aa35f27fba8c1f50b1886706e7efef
    single_hash = None
    if len(hashes) == 1:
        single_hash = hashes[0]
        hashes = None

    for commit in Repository(path_to_repo=repo_url,
                             only_commits=hashes,
                             single=single_hash,
                             num_workers=cf.NUM_WORKERS).traverse_commits():
        cf.logger.debug(f'Processing {commit.hash}')
        try:
            commit_row = {
                'hash': commit.hash,
                'repo_url': repo_url,
                'author': commit.author.name,
                'author_date': commit.author_date,
                'author_timezone': commit.author_timezone,
                'committer': commit.committer.name,
                'committer_date': commit.committer_date,
                'committer_timezone': commit.committer_timezone,
                'msg': commit.msg,
                'merge': commit.merge,
                'parents': commit.parents,
                'num_lines_added': commit.insertions,
                'num_lines_deleted': commit.deletions,
                'dmm_unit_complexity': commit.dmm_unit_complexity,
                'dmm_unit_interfacing': commit.dmm_unit_interfacing,
                'dmm_unit_size': commit.dmm_unit_size,
            }
            commit_files, commit_methods = get_files(commit)
            repo_commits.append(commit_row)
            repo_files.extend(commit_files)
            repo_methods.extend(commit_methods)
        except Exception as e:
            cf.logger.warning(f'Problem while fetching the commits: {e}')
            pass

    if repo_commits:
        df_repo_commits = pd.DataFrame.from_dict(repo_commits)
        df_repo_commits = df_repo_commits[commit_columns]  # ordering the columns
    else:
        df_repo_commits = None

    if repo_files:
        df_repo_files = pd.DataFrame.from_dict(repo_files)
        df_repo_files = df_repo_files[file_columns]  # ordering the columns
    else:
        df_repo_files = None

    if repo_methods:
        df_repo_methods = pd.DataFrame.from_dict(repo_methods)
        df_repo_methods = df_repo_methods[method_columns]  # ordering the
    else:
        df_repo_methods = None

    return df_repo_commits, df_repo_files, df_repo_methods
