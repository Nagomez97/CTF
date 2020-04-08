# import angr
# import claripy

# def main():
# 	# Cargamos el proyecto
#     proj = angr.Project('./test1', load_options={"auto_load_libs": False})

#     # Size estimado
#     sym_arg_size = 20

#     # Construimos un array de bitvectors simbolicos para obtener la flag
#     inp = claripy.BVS("inp", 8*sym_arg_size)
#     # flag = claripy.Concat(flag_chars + [claripy.BVV(b'\n')])


#     # Inicializamos un estado con un argumento simbolico
#     initial_state = proj.factory.full_init_state(
#     	args=['./test1'],
#         add_options=angr.options.unicorn,
#         stdin=inp
#     )

#     # Constrain the first 28 bytes to be non-null and non-newline:
    

#     # Cargamos el simulation manager
#     sm = proj.factory.simulation_manager(initial_state)
#     # Con exploracion DFS
#     sm.use_technique(angr.exploration_techniques.DFS())
#     # Definimos los objetivos a encontrar y evitar
#     # En este caso usarmos offsets porque tenemos un binario sin PIE
#     sm.explore(find=0x401179,avoid=0x401187)

#     # Una vez encuentra un posible candidato, lo resuelve a bytes y lo imprime
#     if len(sm.found) <= 0:
#         print('Anything found')
#         exit()
#     found = sm.found[0]
#     y = found.solver.eval(argv1,cast_to=bytes)
#     print(y)
    
# def test():
#     res = main()
#     print(repr(res))


# if __name__ == '__main__':
#     main()

import angr
import claripy
import subprocess

START = 0x401142
FIND = 0x401179 # part of program that prints the flag
AVOID = 0x401187 # all addresses after a failed check occur on a fixed interval

# Size must be exact
BUF_LEN = 17

def char(state, c):
    '''returns constraints s.t. c is printable'''
    return state.solver.And(c <= '~', c >= ' ')

def main():
    proj = angr.Project('test1')

    print('creating state')
    flag = claripy.BVS('flag', BUF_LEN*8)

    state = proj.factory.blank_state(addr=START, stdin=flag)

    print('adding constaints to stdin')
    
    # Cargamos el simulation manager
    sm = proj.factory.simulation_manager(state)
    # Con exploracion DFS
    sm.use_technique(angr.exploration_techniques.DFS())
    # Definimos los objetivos a encontrar y evitar
    # En este caso usarmos offsets porque tenemos un binario sin PIE
    sm.explore(find=FIND,avoid=AVOID)

    # Una vez encuentra un posible candidato, lo resuelve a bytes y lo imprime
    if len(sm.found) <= 0:
        print('Nothing found');
        exit()
    found = sm.found[0]
    y = found.solver.eval(flag,cast_to=bytes)
    print(y)


if __name__ == '__main__':
    team = main()


