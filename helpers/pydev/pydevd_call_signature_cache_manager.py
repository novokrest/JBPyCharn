__author__ = 'user'

import pydevd_vars
import sys


def get_signature_info(signature):
    return signature.file, signature.name, '\t'.join([arg[1]for arg in signature.args])


class CallSignatureCacheManager:
    def __init__(self, log=None):
        self.cache = {}
        if log:
            self.log = log
        else:
            self.log = open('/home/user/cache_manager_stat', 'a')

    def add(self, signature, return_info=None):
        filename, function, args_type = get_signature_info(signature)

        if not filename in self.cache:
            self.cache[filename] = {}

        module_calls = self.cache[filename]

        if not function in module_calls:
            module_calls[function] = {}

        function_calls = module_calls[function]

        if not args_type in function_calls:
            function_calls[args_type] = {None: None}

        function_calls[args_type][return_info] = None

    def is_repetition(self, signature, return_info=None):
        filename, function, args_type = get_signature_info(signature)

        if filename in self.cache:
            module_calls = self.cache[filename]
            if function in module_calls:
                function_calls = module_calls[function]
                if args_type in function_calls and return_info in function_calls[args_type]:
                    return True

        return False

    def get_cache_size(self):
        return sys.getsizeof(self.cache)

    #only for analysis
    def write_cache_size(self):
        cache_size = self.get_cache_size()
        if self.log:
            self.log.write(str(cache_size) + '\n')