#!/usr/bin/env python3

import atheris
import sys
import types

from atheris.instrument_bytecode import Instrumentor

import fuzz_helpers


def bootstrap_instrumentation(code):
    """
    By default, atheris does not instrument itself (duh).
    To overcome this, we augment the patch_code functionality in order to bypass the check for co_consts.
    :param code: Code object to augment
    :return: The instrumented bytecode object
    """
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
                patch_inst.consts[i] = bootstrap_instrumentation(patch_inst.consts[i])

    return patch_inst.to_code()


# Create an instrumented version of atheris' patch_code function
instrumented_patch_code_bc = bootstrap_instrumentation(atheris.patch_code.__code__)
instrumented_patch_code = types.FunctionType(instrumented_patch_code_bc, atheris.patch_code.__globals__,
                                                 atheris.patch_code.__name__, atheris.patch_code.__defaults__,
                                                 atheris.patch_code.__closure__)


def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        code = compile(fdp.ConsumeRemainingBytes(), "<fuzz>", "exec")
        if code:
            instrumented_patch_code(code, True, True)
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
