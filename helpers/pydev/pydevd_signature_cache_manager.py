__author__ = 'user'

import pydevd_vars
import sys


def get_signature_info(signature):
    return signature.file, signature.name, ' '.join([arg[1]for arg in signature.args])


class SignatureCacheManager(object):
    def __init__(self, log=None):
        self._cache = {}
        self.log = log

    def get_cache_size(self):
        return sys.getsizeof(self._cache)

    #only for analysis
    def write_cache_size(self):
        cache_size = self.get_cache_size()
        if self.log:
            self.log.write(str(cache_size) + '\n')


class CallSignatureCacheManager(SignatureCacheManager):
    def __init__(self, log=None):
        SignatureCacheManager.__init__(self, log)

    def add(self, signature):
        filename, name, args_type = get_signature_info(signature)

        if not filename in self._cache:
            self._cache[filename] = {}

        calls_from_file = self._cache[filename]

        if not name in calls_from_file:
            calls_from_file[name] = {}

        name_calls = calls_from_file[name]

        if not args_type in name_calls:
            name_calls[args_type] = {}

    def is_repetition(self, signature):
        filename, name, args_type = get_signature_info(signature)
        if filename in self._cache and name in self._cache[filename] and args_type in self._cache[filename][name]:
            return True
        return False

    def is_first_call(self, signature):
        filename, name = get_signature_info(signature)[:-1]
        if filename in self._cache and name in self._cache[filename]:
            return False
        return True

    def print_cache(self):
        for filename, module_calls in self._cache.items():
            for name, function_calls in module_calls.items():
                for args_type, value in function_calls.items():
                    print "filename=%s, name=%s, args_type=%s, value=%s" % (filename, name, args_type, value)


class ReturnSignatureCacheManager(SignatureCacheManager):
    def __init__(self, log=None):
        SignatureCacheManager.__init__(self, log)

    def add(self, signature, return_info):
        filename, name = get_signature_info(signature)[:-1]

        if not filename in self._cache:
            self._cache[filename] = {}

        calls_from_file = self._cache[filename]

        if not name in calls_from_file:
            calls_from_file[name] = {}

        returns = calls_from_file[name]
        returns[return_info] = None

    def is_repetition(self, signature, return_info):
        filename, name = get_signature_info(signature)[:-1]
        if filename in self._cache and name in self._cache[filename] and return_info in self._cache[filename][name]:
            return True
        return False