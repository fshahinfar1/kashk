import os
import sys
import subprocess


curdir = os.path.abspath(os.path.dirname(__file__))


def run_suite(suite):
    print('Running suite:', suite)
    tests = 0
    fails = 0
    suite_dir = os.path.join(curdir, suite)
    list_of_files = os.listdir(suite_dir)
    list_of_tests = filter(lambda x: os.path.isfile(os.path.join(suite_dir, x)) and x.startswith('test_'), list_of_files)
    for test in list_of_tests:
        tests += 1
        failed = False
        info = ''

        test_path = os.path.join(suite_dir, test)
        cmd = ['python3', test_path]
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        ret_code = proc.returncode
        if ret_code != 0:
            failed = True
            info += '[ret code]'

        err_msg = proc.stderr.decode()
        if len(err_msg) > 0:
            failed = True
            info += '[stderr]'

        if failed:
            fails += 1

        flag = 'FAILED' if failed else 'PASSED'
        color_begin = '\033[31m' if failed else '\033[34m'
        color_end   = '\033[0m'
        print(f'{color_begin}    * {test:.32}: {flag} {info}{color_end}')
    return tests, fails


def main():
    list_of_suites = os.listdir(curdir)
    list_of_suites = list(filter(lambda x: os.path.isdir(os.path.join(curdir, x)) and x.startswith('suite_'), list_of_suites))

    print('Which suite to run? [A for all]')
    for i, suite in enumerate(list_of_suites):
        print(i, suite)
    choice = input('choice: ')
    if choice == 'A' or choice == 'a':
        tests = 0
        fails = 0
        for suite in list_of_suites:
            t, f = run_suite(suite)
            tests += t
            fails += f
    else:
        index = int(choice)
        suite = list_of_suites[index]
        tests, fails = run_suite(suite)

    print('Failed tests:', f'{fails}/{tests}')


if __name__ == '__main__':
    main()
