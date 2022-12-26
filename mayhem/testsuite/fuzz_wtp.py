#!/usr/bin/env python3

import sys

import atheris
import types
from atheris.instrument_bytecode import Instrumentor

import fuzz_helpers
import atheris


def augmented_patch_code(code):
    # Override the patch_code function to not have __ATHERIS_INSTRUMENTED__ in the code object
    patch_inst = Instrumentor(code)
    patch_inst.trace_control_flow()
    patch_inst.trace_data_flow()
    # Repeat this for all nested code objects
    for i in range(len(patch_inst.consts)):
        if isinstance(patch_inst.consts[i], types.CodeType):
            if (patch_inst.consts[i].co_name == "<lambda>" or
                    (patch_inst.consts[i].co_name == "<module>") or
                    patch_inst.consts[i].co_name[0] != "<" or
                    patch_inst.consts[i].co_name[-1] != ">"):
                patch_inst.consts[i] = augmented_patch_code(patch_inst.consts[i])

    return patch_inst.to_code()


instrumented_patch_code = augmented_patch_code(atheris.patch_code.__code__)
atheris.patch_code = types.FunctionType(instrumented_patch_code, atheris.patch_code.__globals__,
                                        atheris.patch_code.__name__, atheris.patch_code.__defaults__,
                                        atheris.patch_code.__closure__)


def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        code = compile(fdp.ConsumeRemainingBytes(), "<fuzz>", "exec")
        if code:
            atheris.patch_code(code, True, True)
    except (SyntaxError, UnicodeDecodeError):
        return -1
    except ValueError as e:
        if 'source code' in str(e):
            return -1
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
