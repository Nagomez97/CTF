import angr
import claripy

def main():
	# Cargamos el proyecto
    proj = angr.Project('./test1', load_options={"auto_load_libs": False})

    # Size estimado del argumento
    sym_arg_size = 8

    # Variable sobre la que simular el argumento (bitvector)
    argv1 = claripy.BVS("argv1",  8 * sym_arg_size)

    # Inicializamos un estado con un argumento simbolico
    initial_state = proj.factory.full_init_state(
    	args=['./test1', argv1]
    )

    # Cargamos el simulation manager
    sm = proj.factory.simulation_manager(initial_state)
    # Con exploracion DFS
    sm.use_technique(angr.exploration_techniques.DFS())
    # Definimos los objetivos a encontrar y evitar
    # En este caso usarmos offsets porque tenemos un binario sin PIE
    sm.explore(find=0x4011a3,avoid=0x40118c)

    # Una vez encuentra un posible candidato, lo resuelve a bytes y lo imprime
    found = sm.found[0]
    y = found.solver.eval(argv1,cast_to=bytes)
    print(y)
    
def test():
    res = main()
    print(repr(res))


if __name__ == '__main__':
    main()