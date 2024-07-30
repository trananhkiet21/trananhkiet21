

from ghidra.program.model.listing import Function
from ghidra.program.model.scalar import Scalar

def get_called_functions(func):
    # Iterate over instructions, yield addresses of calls to functions starting with "FUN_00"
    for instr in currentProgram.getListing().getInstructions(func.getBody(), True):
        if instr.getFlowType().isCall():
            for ref in instr.getReferencesFrom():
                called_func = getFunctionAt(ref.getToAddress())
                if called_func and called_func.getName().startswith("FUN_00"):
                    yield called_func.getEntryPoint()

def get_flag_char(address):
    # Given an address, get instruction at offset 0x9, convert operand to address,
    # then retrieve and return byte at this address as character
    target_address = address.add(0x9)
    instruction = currentProgram.getListing().getInstructionAt(target_address)
    operand = instruction.getOpObjects(1)[0]
    if isinstance(operand, Scalar):
        char_addr = toAddr(operand.getValue())
        return chr(currentProgram.getMemory().getByte(char_addr))
    return None

# Get the main function
main_function = getFunctionAt(toAddr(0x0010298a)) # Entry point of main function visible from disassembler

# Use list comprehension to generate list of flag characters
flag = [get_flag_char(addr) for addr in get_called_functions(main_function) if get_flag_char(addr) is not None]

# Print flag
print(''.join(flag))