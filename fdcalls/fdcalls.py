#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import r2pipe
import argparse
import subprocess


dangerous_functions = ['sym.imp.system', 'sym.imp.popen', 'sym.imp.execve']
command_injection_addr = []
all_used_dynamic_libraries = []


r2_fd = {}
'''
all related dynamic link libraries
{'elf1':['libc1.so', 'libc2.so'], 'elf2':['libc3.so', 'libc4.so']}
'''
dynamic_libraries = {}
'''
The functions defined in this elf themselves
{'elf1':['func1', 'func2'], 'elf2':['func3', 'func4']}
'''
functions_self_defined = {}
'''
The functions defined in other libc
{'elf1':['func1', 'func2'], 'elf2':['func3', 'func4']}
'''
functions_other_defined = {}
'''
Functions called within various functions in the dynamic link library
{'libc.so1':{'fun':['func1', 'func2'], 'fun2':['func2', 'func3']}, 'libc2.so':{'fun':['func1', 'func2'], 'fun2':['func2', 'func3']}}
'''
libraries_called_functions = {}
'''
Functions defined in which library
{'func1':'libc1.so', 'fun2':'libc2.so'}
'''
function_to_library = {}
'''
Dangerous function call chain
{'fun1': ['fun2', 'system'], 'popen': ['popen'], 'execve': ['execve']}
'''
dangerous_functions_chain = {'sym.imp.system': ['system'], 'sym.imp.popen': ['popen'], 'sym.imp.execve': ['execve']}

def init():
    print("""

         .o88o.       .o8                      oooo  oooo           
         888 `"      "888                      `888  `888           
        o888oo   .oooo888   .ooooo.   .oooo.    888   888   .oooo.o 
         888    d88' `888  d88' `"Y8 `P  )88b   888   888  d88(  "8 
         888    888   888  888        .oP"888   888   888  `"Y88b.  
         888    888   888  888   .o8 d8(  888   888   888  o.  )88b 
        o888o   `Y8bod88P" `Y8bod8P' `Y888""8o o888o o888o 8""888P'
                                                            
    """)

def add_colour(string, colour = 'white'):
    if colour == 'red':
        return f'\033[1;31m{string}\033[0m'
    elif colour == 'yellow':
        return f'\033[1;33m{string}\033[0m'
    elif colour == 'magenta':
        return f'\033[1;35m{string}\033[0m'
    elif colour == 'cyan':
        return f'\033[1;36m{string}\033[0m'
    else:
        return f'\033[1;30m{string}\033[0m'

# Obtain the relative path of the file
def get_path_by_filename(filename, file_system_path):
    output = subprocess.check_output(['find', file_system_path, '-name', filename]).decode('utf-8')
    for line in output.split('\n'):
        return line

# Obtain relevant dynamic link library names
def get_dynamic_libraries(r2fd, file_system_path):
    '''
    output = subprocess.check_output(['readelf', '-d', target_file_path]).decode('utf-8')
    libraries = []
    for line in output.split('\n'):
        if 'Shared library' in line:
            library = line.split('[')[-1].split(']')[0]
            library = get_path_by_filename(library, file_system_path)
            libraries.append(library)
    '''
    libraries = []
    libs = r2fd.cmdj('ilj')
    for lib in libs:
        library = get_path_by_filename(lib, file_system_path)
        libraries.append(library)

    return libraries

# Obtain function names in target file
def get_function_names(r2fd, mode):
    function_names = []
    function_name = ''
    functions = r2fd.cmdj('aflj')
    if mode == 0:
        for function in functions:
            # print(function)
            if 'sym.imp' in function['name']:
                function_name = function['name']
                # print(function_name)
                function_names.append(function_name) 
    else:
        for function in functions:
            # print(function)
            if 'sym.imp' not in function['name']:
                function_name = function['name']
                # print(function_name)
                function_names.append(function_name) 
    return function_names

# start r2 analysis
def r2_start_analysis(filepath):
    r2fd = r2pipe.open(filepath)
    r2fd.cmd('aaa')
     
    return r2fd

# get architecture of binary
def get_architecture(r2fd):
    info = json.loads(r2fd.cmd('iIj'))
    return info["arch"]

# Obtain the function called internally from the function
'''
for example:
    int FunA(){
        system(...);
        printf(...);
    }
    we will get:
    function_called_functions[A] = ['system', 'printf']

    differnet arch may be a little difference while coding
'''
def get_functions_called(r2fd, filename, arch):

    function_called_functions = {}
    functions = []
    function_name = ''
    length = 0
    
    if arch == 'arm':
        for fun in functions_self_defined[filename]:
            # print(fun)
            functions = []
            disassembly = r2fd.cmd(f'pdf @ {fun} 2>/dev/null')
            for line in disassembly.split('\n'):
                function_name = ''
                if 'sym' in line:
                    # print(line)
                    line1 = line[line.rfind('sym'):]
                    if line1.find(' ') != -1:
                        length = line1.find(' ')
                    else:
                        length = len(line1)
                    # print(length)
                    # print(line[line.find('sym'):line.find('sym')+length])
                    function_name = line[line.find('sym'):line.find('sym')+length]
                elif 'fcn' in line:
                    # print(line)
                    line1 = line[line.find('fcn'):]
                    if line1.find(' ') != -1:
                        length = line1.find(' ')
                    else:
                        length = len(line1)
                    # print(length)
                    # print(line[line.find('fcn'):line.find('fcn')+length])
                    function_name = line[line.find('fcn'):line.find('fcn')+length]
                if function_name != '' and function_name!=fun and function_name not in functions:
                    functions.append(function_name)
            function_called_functions[fun] = functions
            # print(function_called_functions[fun])
        # print(function_called_functions)
    if arch == 'mips':
        for fun in functions_self_defined[filename]:
            # print(fun)
            functions = []
            disassembly = r2fd.cmd(f'pdf @ {fun} 2>/dev/null')
            for line in disassembly.split('\n'):
                function_name = ''
                if 'sym' in line and 'XREF' not in line:
                    # print(line)
                    line1 = line[line.rfind('sym'):]
                    if line1.find(' ') != -1:
                        length = line1.find(' ')
                    else:
                        length = len(line1)
                    # print(length)
                    # print(line[line.find('sym'):line.find('sym')+length])
                    function_name = line[line.find('sym'):line.find('sym')+length]
                elif 'fcn' in line and 'XREF' not in line:
                    # print(line)
                    line1 = line[line.find('fcn'):]
                    if line1.find(' ') != -1:
                        length = line1.find(' ')
                    else:
                        length = len(line1)
                    # print(length)
                    # print(line[line.find('fcn'):line.find('fcn')+length])
                    function_name = line[line.find('fcn'):line.find('fcn')+length]
                if function_name != '' and function_name!=fun and function_name not in functions:
                    functions.append(function_name)
            function_called_functions[fun] = functions
            # print(function_called_functions[fun])
        # print(function_called_functions)
    return function_called_functions

# Obtaining a dangerous function call chain
'''
for example:
    int FunA(){
        FunB();
        puts(...);
    }
    int FunB(){
        system(...);
        printf(...);
    }
    we will get:
    dangerous_fun[A] = ['FunB', 'system']
    dangerous_fun[B] = ['system']
'''
def get_dangerous_chains(dangerous_fun, pre_fun):
    dangerous_fun = [dangerous_fun]
    
    dangerous_fun+= dangerous_functions_chain[pre_fun]
    return dangerous_fun
    

def find_command_injection(r2fd, filename):
    cmdinjection = []
    banned_funcs = []

    for fun in functions_self_defined[filename]:
        # print(fun)
        disassembly = r2fd.cmd(f'pdf @ {fun} 2>/dev/null')
        for line in disassembly.split('\n'):
            for func in dangerous_functions:
                func_chain = ''
                if func in line and fun != func:
                    addr = line[line.find('0x'):line.find('0x')+10]
                    cnt = 0    
                    func_chain+= '[+] ['
                    func_chain+= add_colour(filename, 'cyan') + '] '
                    func_chain+= add_colour(fun, 'red') + ' ('
                    func_chain+= add_colour(addr, 'magenta') + ') '
                    
                    for f in dangerous_functions_chain[func]:
                        if cnt:
                            func_chain+= '\n    -> '
                        else:
                            func_chain+= '-> '
                        s = ''
                        if 'sym.' in f:
                            s = f[f.find('sym.'):]
                            s = s.replace('imp.', '')
                            func_chain+= '['
                            func_chain+= add_colour(function_to_library[s], 'cyan')
                            func_chain+= '] '
                            func_chain+= add_colour(s, 'yellow')
                            cnt+= 1
                        elif 'fcn.' in f:
                            s = f[f.find('fcn.'):]
                            func_chain+= '['
                            func_chain+= add_colour(function_to_library[s], 'cyan')
                            func_chain+= '] '
                            func_chain+= add_colour(s, 'yellow')
                            cnt+= 1
                        else:
                            func_chain+= add_colour(f, 'yellow')
                            cnt+= 1
                    # print(func_chain)
                    cmdinjection.append(func_chain)

                    # print(fun + f'({addr}) ->' + func)
                    # print(dangerous_functions_chain[func])
                    # print(line)
    return cmdinjection

# Add the filename before the functionname
def add_filename_to_function(filename, functionname):
    if 'sym.imp' in functionname:
        return functionname
    else:
        return filename + '.' + functionname

def show_more_dangerous_function():
    print("[+] more dangerous functions")
    for fun in dangerous_functions:
        if 'sym.imp' in fun:
            fun = fun.replace('sym.imp', 'sym')
            if fun in function_to_library.keys():
            	print('[' + add_colour(function_to_library[fun], 'cyan') + '] ' + add_colour(fun, 'yellow'))

def main():
    parser = argparse.ArgumentParser(description="fdcalls to help analysis")
    parser.version = "1.3"

    parser.add_argument('-b', '--target_binary_path', type=str, default='', help='path to target binary')
    parser.add_argument('-d', '--file_system_directory_path', type=str, default='', help='path to firmware file system directory')
    parser.add_argument('-l', '--level', type=int, default=0, help='level of analysis')
    parser.add_argument('-v', action='version', help='print the version and exit')
    args = parser.parse_args()

    target_filepath = args.target_binary_path
    file_system_path = args.file_system_directory_path
    level = args.level
    
    if target_filepath == '':
        print('./dcalls.py -b [path/to/target_binary] -d [path/to/file_system_dir] -a [arch] -l [level=0]')
        exit(0)
    
    init()

    print("[*] Collecting and analysing binaries ...")
    r2_fd[target_filepath] = r2_start_analysis(target_filepath)
    dynamic_libraries[target_filepath] = get_dynamic_libraries(r2_fd[target_filepath], file_system_path)
    for f in dynamic_libraries[target_filepath]:
        r2_fd[f] = r2_start_analysis(f)
        all_used_dynamic_libraries.append(f)
        dynamic_libraries[f] = get_dynamic_libraries(r2_fd[f], file_system_path)
        for lib in dynamic_libraries[f]:
            if lib not in all_used_dynamic_libraries:
                all_used_dynamic_libraries.append(lib)
        # print(f + "=> ", end = '')
        # print(get_dynamic_libraries(r2_fd[f], file_system_path))
    
    for f in all_used_dynamic_libraries:
        if f not in dynamic_libraries.keys():
            r2_fd[f] = r2_start_analysis(f)
            dynamic_libraries[f] = get_dynamic_libraries(r2_fd[f], file_system_path)
            # print(f + "=> ", end = '')
            # print(get_dynamic_libraries(r2_fd[f], file_system_path))
    # print(all_used_dynamic_libraries)
    architecture = get_architecture(r2_fd[target_filepath])
    print("[+] Collect and analyse success")

    print("[*] Identifying functions in elf and libraries ...")
    functions_other_defined[target_filepath] = get_function_names(r2_fd[target_filepath], 0)
    for f in all_used_dynamic_libraries:
        functions_other_defined[f] = get_function_names(r2_fd[f], 0)
    # print(functions_other_defined)
    
    functions_self_defined[target_filepath] = get_function_names(r2_fd[target_filepath], 1)
    for lib in all_used_dynamic_libraries:
        functions_self_defined[lib] = get_function_names(r2_fd[lib], 1)
        for fun in functions_self_defined[lib]:
            function_to_library[fun] = lib
    # print(functions_self_defined['./bin/pucfu'])
    # print(functions_self_defined)
    # print(function_to_library)
    print("[+] Identifying functions success")
    
    print("[*] Enumerateing call paths in libraries ...")
    for lib in all_used_dynamic_libraries:
        libraries_called_functions[lib] = get_functions_called(r2_fd[lib] ,lib, architecture)
        # print(lib)
        # print(get_functions_called(r2_fd[lib] ,lib, architecture))
    # print(libraries_called_functions)
    print("[+] Enumerateing call paths in libraries success")

    # Search dangerous functions and add them to dangerous_functions
    print("[*] Searching for dangerous functions in libraries ...")
    dangerous_functions_now_len = len(dangerous_functions)
    dangerous_functions_old_len = 0
    while(dangerous_functions_now_len > dangerous_functions_old_len):
        for lib in libraries_called_functions.keys():
            for fun in libraries_called_functions[lib].keys():
                if 'sym' in fun:
                    func1 = add_filename_to_function(lib, fun)
                    func2 = fun.replace('sym', 'sym.imp')
                    for called_fun in libraries_called_functions[lib][fun]:
                        if add_filename_to_function(lib, called_fun) in dangerous_functions and func1 not in dangerous_functions:
                            dangerous_functions.append(func1)
                            dangerous_functions.append(func2)
                            dangerous_functions_chain[func1] = get_dangerous_chains(func1, add_filename_to_function(lib, called_fun))
                            dangerous_functions_chain[func2] = get_dangerous_chains(func2, add_filename_to_function(lib, called_fun))
                            break

                elif 'fcn' in fun:
                    func = add_filename_to_function(lib, fun)
                    for called_fun in libraries_called_functions[lib][fun]:
                        if add_filename_to_function(lib, called_fun) in dangerous_functions and func not in dangerous_functions:
                            dangerous_functions.append(func)
                            dangerous_functions_chain[func] = get_dangerous_chains(func, add_filename_to_function(lib, called_fun))
                            break

        dangerous_functions_old_len = dangerous_functions_now_len
        dangerous_functions_now_len = len(dangerous_functions)
    # print(dangerous_functions)
    # print(dangerous_functions_chain)
    print("[*] Searching dangerous functions finish")

    print("[*] Searching dangerous called in binary ...")
    command_injection_addr = find_command_injection(r2_fd[target_filepath], target_filepath)
    # print results
    for s in command_injection_addr:
        print(s)
    print("[+] fdcalls finish")
    
    if level:
        show_more_dangerous_function()

if __name__ == '__main__':
    main()
