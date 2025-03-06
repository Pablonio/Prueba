import sys
import time
import numpy as np
import matplotlib.pyplot as plt
from colorama import Fore, Style, init
from qiskit import QuantumCircuit
from qiskit.compiler import assemble, transpile
from qiskit_aer import AerSimulator
from qiskit.quantum_info import Statevector
from qiskit.visualization import (
    plot_bloch_multivector,
    plot_state_qsphere,
    plot_histogram,
    circuit_drawer
)
try:
    # Para entornos Jupyter, si está disponible
    from IPython.display import display
    HAS_IPYTHON = True
except ImportError:
    HAS_IPYTHON = False

init(autoreset=True)

# ----------------------- FUNCIONES AUXILIARES -----------------------
def print_title(title):
    """Muestra títulos con formato especial."""
    print(f"\n{Fore.YELLOW}{'═'*40}")
    print(f"{Fore.CYAN}➤ {title.upper()}")
    print(f"{Fore.YELLOW}{'═'*40}{Style.RESET_ALL}")

def animated_progress(message, duration=2):
    """Muestra una animación de progreso en consola."""
    chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    start = time.time()
    while time.time() - start < duration:
        for ch in chars:
            sys.stdout.write(f"\r{Fore.GREEN}{ch} {message}...{Style.RESET_ALL}")
            sys.stdout.flush()
            time.sleep(0.1)
    print("\r" + " " * 50 + "\r", end="")

def show_state_vector(state, title="Vector de Estado"):
    """Muestra el vector de estado de forma formateada."""
    print(f"\n{Fore.MAGENTA}{title}:")
    n = int(np.log2(len(state.data)))
    for i, amp in enumerate(state.data):
        bits = bin(i)[2:].zfill(n)
        print(f"|{bits}⟩: {amp.real:.3f} + {amp.imag:.3f}i")

def safe_display(drawable, output='mpl'):
    """Muestra el dibujo del circuito de forma segura según el entorno."""
    if HAS_IPYTHON:
        display(circuit_drawer(drawable, output=output))
    else:
        plt.figure()
        plt.imshow(circuit_drawer(drawable, output=output).get_array())
        plt.axis('off')
        plt.show()

# ----------------------- DEMO 0: MEDICIÓN BÁSICA MEJORADA -----------------------
def demo_basic_measurement():
    print_title("Medición Básica de 1 Qubit")
    # Mostrar estado inicial en la esfera de Bloch
    state = Statevector.from_label('0')
    print(f"\n{Fore.BLUE}Estado inicial del qubit (Bloch Sphere):")
    plot_bloch_multivector(state)
    plt.show()
    
    # Crear circuito con 1 qubit y 1 bit clásico y medir
    qc = QuantumCircuit(1, 1)
    qc.measure(0, 0)
    
    print(f"\n{Fore.CYAN}Ejecutando medición del qubit...")
    animated_progress("Midiendo qubit", duration=2)
    
    backend = AerSimulator()
    job = transpile(qc, backend)
    result = backend.run(job).result()
    counts = result.get_counts()
    
    print(f"\n{Fore.GREEN}Resultado de la medición:")
    plot_histogram(counts)
    plt.show()
    input("\nPresione Enter para continuar...")

# ----------------------- DEMO 1: SISTEMA MULTI-QUBIT -----------------------
def demo_multivectors():
    print_title("Sistema de Múltiples Qubits y Superposición")
    try:
        n = int(input("Ingrese el número de qubits (por ejemplo, 3): "))
        if n < 1:
            raise ValueError
    except ValueError:
        print(f"{Fore.RED}Entrada inválida. Se usará 3 qubits por defecto.")
        n = 3

    qc = QuantumCircuit(n)
    qc.h(range(n))  # Aplicar Hadamard a cada qubit para crear superposición.
    
    state = Statevector.from_instruction(qc)
    print(f"\n{Fore.BLUE}Estado cuántico de {n} qubits (Q-sphere):")
    plot_state_qsphere(state)
    plt.show()
    
    print(f"\n{Fore.CYAN}Cada qubit añade una dimensión:")
    for i in range(n+1):
        print(f"{i} qubit{'s' if i != 1 else ''}: {2**i} estados posibles")
        time.sleep(0.5)
    
    show_state_vector(state)
    input("\nPresione Enter para continuar...")

# ----------------------- DEMO 2: ALGORITMO DE GROVER MEJORADO -----------------------
def demo_grover():
    print_title("Algoritmo de Búsqueda de Grover")
    marked = input("Ingrese el estado marcado de 2 bits (ej.: 11, 10, 01 o 00): ").strip()
    if len(marked) != 2 or any(bit not in "01" for bit in marked):
        print(f"{Fore.RED}Entrada inválida. Se usará '11' por defecto.")
        marked = "11"
    
    def oracle(qc, qubits, target):
        for i, bit in enumerate(target):
            if bit == '0':
                qc.x(qubits[i])
        qc.cz(qubits[0], qubits[1])
        for i, bit in enumerate(target):
            if bit == '0':
                qc.x(qubits[i])
    
    def diffuser(qc, qubits):
        qc.h(qubits)
        qc.x(qubits)
        qc.h(qubits[1])
        qc.cx(qubits[0], qubits[1])
        qc.h(qubits[1])
        qc.x(qubits)
        qc.h(qubits)
    
    qc = QuantumCircuit(2, 2)
    print(f"\n{Fore.BLUE}Inicializando sistema en superposición...")
    qc.h([0, 1])
    
    print(f"{Fore.YELLOW}Aplicando oráculo para marcar el estado |{marked}⟩...")
    oracle(qc, [0, 1], marked)
    print(f"{Fore.YELLOW}Aplicando difusor para amplificar la probabilidad...")
    diffuser(qc, [0, 1])
    qc.measure([0, 1], [0, 1])
    
    animated_progress("Ejecutando Grover", duration=2)
    
    backend = AerSimulator()
    job = transpile(qc, backend)
    result = backend.run(job).result()
    counts = result.get_counts()
    
    print(f"\n{Fore.GREEN}Resultados de Grover:")
    plot_histogram(counts)
    plt.show()
    input("\nPresione Enter para continuar...")

# ----------------------- DEMO 3: SIMULADOR CUÁNTICO INTERACTIVO -----------------------
def interactive_simulator():
    print_title("Simulador Cuántico Interactivo")
    qc = QuantumCircuit(1)
    while True:
        print("\nOpciones disponibles:")
        print("1. Aplicar compuerta H")
        print("2. Aplicar compuerta X")
        print("3. Aplicar compuerta Y")
        print("4. Aplicar compuerta Z")
        print("5. Medir qubit")
        print("6. Reiniciar circuito")
        print("7. Salir a menú principal")
        choice = input("Elija una opción: ").strip()
        
        if choice == '1':
            qc.h(0)
        elif choice == '2':
            qc.x(0)
        elif choice == '3':
            qc.y(0)
        elif choice == '4':
            qc.z(0)
        elif choice == '5':
            qc.measure_all()
            backend = AerSimulator()
            result = backend.run(transpile(qc, backend)).result()
            print(f"\n{Fore.GREEN}Resultado de la medición:", result.get_counts())
            break
        elif choice == '6':
            qc = QuantumCircuit(1)
            print(f"{Fore.CYAN}Circuito reiniciado.")
        elif choice == '7':
            break
        else:
            print(f"{Fore.RED}Opción no válida.")
        
        # Mostrar estado actual en la esfera de Bloch
        state = Statevector.from_instruction(qc)
        plot_bloch_multivector(state)
        plt.show()
    input("\nPresione Enter para continuar...")

# ----------------------- DEMO 4: TELETRANSPORTACIÓN CUÁNTICA MEJORADA -----------------------
def demo_teleportation():
    print_title("Teletransportación Cuántica")
    print("Elija una compuerta para preparar el estado en el qubit 0 (opciones: H, X, Y, Z o Ninguna).")
    puerta = input("Ingrese la compuerta deseada para el qubit 0: ").strip().upper()
    
    qc = QuantumCircuit(3, 3)
    print("\nCreando par entrelazado entre qubits 1 y 2...")
    qc.h(1)
    qc.cx(1, 2)
    
    print("Preparando estado en el qubit 0...")
    if puerta == "H":
        qc.h(0)
    elif puerta == "X":
        qc.x(0)
    elif puerta == "Y":
        qc.y(0)
    elif puerta == "Z":
        qc.z(0)
    else:
        print("Ninguna compuerta aplicada; el qubit 0 permanece en |0⟩.")
    
    qc.cx(0, 1)
    qc.h(0)
    qc.measure([0, 1], [0, 1])
    qc.cx(1, 2)
    qc.cz(0, 2)
    qc.measure(2, 2)
    
    print("\nCircuito de Teletransportación:")
    if HAS_IPYTHON:
        display(circuit_drawer(qc, output='mpl'))
    else:
        print(qc.draw(output='text'))
    animated_progress("Ejecutando teletransportación", duration=2)
    
    backend = AerSimulator()
    job = transpile(qc, backend)
    result = backend.run(job).result()
    counts = result.get_counts()
    
    print(f"\n{Fore.GREEN}Resultados de Teletransportación:")
    plot_histogram(counts)
    plt.show()
    input("\nPresione Enter para continuar...")

# ----------------------- DEMO 5: SIMULACIÓN CON RUIDO MEJORADA -----------------------
def demo_noise_simulation():
    print_title("Simulación con Ruido")
    from qiskit.aer.noise import NoiseModel, depolarizing_error
    print("Se simula un circuito de 1 qubit con compuerta H, comparando resultados ideales y con ruido (10% error depolarizante).")
    
    qc = QuantumCircuit(1, 1)
    qc.h(0)
    qc.measure(0, 0)
    
    backend_ideal = AerSimulator()
    job_ideal = transpile(qc, backend_ideal)
    result_ideal = backend_ideal.run(assemble(job_ideal, shots=1024)).result()
    counts_ideal = result_ideal.get_counts()
    
    error = depolarizing_error(0.1, 1)
    noise_model = NoiseModel()
    noise_model.add_all_qubit_quantum_error(error, ['h'])
    
    backend_noisy = AerSimulator(noise_model=noise_model)
    job_noisy = transpile(qc, backend_noisy)
    result_noisy = backend_noisy.run(assemble(job_noisy, shots=1024)).result()
    counts_noisy = result_noisy.get_counts()
    
    print(f"\n{Fore.BLUE}Resultado ideal:")
    plot_histogram(counts_ideal)
    plt.show()
    print(f"\n{Fore.BLUE}Resultado con ruido:")
    plot_histogram(counts_noisy)
    plt.show()
    input("\nPresione Enter para continuar...")

# ----------------------- DEMO 6: OPTIMIZACIÓN CUÁNTICA MEJORADA -----------------------
def demo_optimization():
    print_title("Optimización Cuántica (Parámetro RY)")
    from scipy.optimize import minimize
    import numpy as np

    print("Se optimiza el parámetro theta en una compuerta RY para maximizar la probabilidad de medir el estado |1⟩.")
    def objective(theta):
        return -np.sin(theta[0]/2)**2

    initial_theta = [0.0]
    result = minimize(objective, initial_theta, bounds=[(0, 2*np.pi)])
    optimal_theta = result.x[0]
    max_prob = -result.fun
    print(f"\nÁngulo óptimo: {optimal_theta:.4f} rad (P(1) = {max_prob:.4f})")
    
    qc = QuantumCircuit(1, 1)
    qc.ry(optimal_theta, 0)
    qc.measure(0, 0)
    
    backend = AerSimulator()
    job = transpile(qc, backend)
    result = backend.run(assemble(job, shots=1024)).result()
    counts = result.get_counts()
    
    print(f"\n{Fore.GREEN}Resultados del circuito optimizado:")
    plot_histogram(counts)
    plt.show()
    input("\nPresione Enter para continuar...")

# ----------------------- DEMO 7: COMPUERTA LÓGICA Y OPERACIONES MEJORADA -----------------------
def demo_logical_gate():
    print_title("Compuertas Lógicas y Visualización de Multiarray (CNOT)")
    # Solicitar estado inicial para 2 qubits
    initial_state = input("Ingrese el estado inicial de 2 qubits (ej.: 00, 01, 10, 11): ").strip()
    if len(initial_state) != 2 or any(bit not in "01" for bit in initial_state):
        print(f"{Fore.RED}Entrada inválida. Se usará '00' por defecto.")
        initial_state = "00"
    
    qc = QuantumCircuit(2, 2)
    # Preparar el estado inicial: aplicar X donde corresponda
    for i, bit in enumerate(initial_state):
        if bit == '1':
            qc.x(i)
    
    print("\nCircuito inicial (estado preparado manualmente):")
    if HAS_IPYTHON:
        display(circuit_drawer(qc, output='mpl'))
    else:
        print(qc.draw(output='text'))
    
    state_init = Statevector.from_instruction(qc)
    print("\nVector de estado inicial (multiarray, dimensión 2^2):")
    show_state_vector(state_init)
    
    # Aplicar compuerta CNOT: qubit 0 controla y qubit 1 es el objetivo
    qc.cx(0, 1)
    print("\nCircuito después de aplicar CNOT:")
    if HAS_IPYTHON:
        display(circuit_drawer(qc, output='mpl'))
    else:
        print(qc.draw(output='text'))
    
    state_final = Statevector.from_instruction(qc)
    print("\nVector de estado final (multiarray actualizado):")
    show_state_vector(state_final)
    
    qc.measure([0, 1], [0, 1])
    backend = AerSimulator()
    job = transpile(qc, backend)
    result = backend.run(assemble(job, shots=1024)).result()
    counts = result.get_counts()
    print("\nResultados de la medición (estadísticas clásicas):")
    plot_histogram(counts)
    plt.show()
    input("\nPresione Enter para continuar...")

# ----------------------- DEMO 8: INFORMACIÓN SOBRE SHOR -----------------------
def show_shor_info():
    print_title("Algoritmo de Shor")
    print("El Algoritmo de Shor factoriza números de forma exponencialmente más rápida que los métodos clásicos.")
    print("Esto tiene implicaciones importantes en criptografía, ya que muchos sistemas se basan en la dificultad de factorizar números grandes.")
    print("La implementación completa de Shor es compleja y requiere muchos qubits y una arquitectura robusta.")
    print("Para profundizar, consulta la documentación oficial de Qiskit:")
    print("https://qiskit.org/textbook/ch-algorithms/shor.html")
    input("\nPresione Enter para continuar...")

# ----------------------- MENÚ PRINCIPAL MEJORADO -----------------------
def main():
    menu = {
        '0': ("Medición Básica de 1 Qubit", demo_basic_measurement),
        '1': ("Sistema Multi-Qubit y Superposición", demo_multivectors),
        '2': ("Algoritmo de Grover", demo_grover),
        '3': ("Simulador Cuántico Interactivo", interactive_simulator),
        '4': ("Teletransportación Cuántica", demo_teleportation),
        '5': ("Simulación con Ruido", demo_noise_simulation),
        '6': ("Optimización Cuántica (Parámetro RY)", demo_optimization),
        '7': ("Compuerta Lógica (CNOT) y Multiarray", demo_logical_gate),
        '8': ("Información sobre Shor", show_shor_info),
        '9': ("Salir", None)
    }
    
    while True:
        print_title("Laboratorio de Computación Cuántica")
        for key in sorted(menu.keys()):
            print(f"{Fore.GREEN}[{key}] {menu[key][0]}")
        choice = input("\nSeleccione un experimento: ").strip()
        if choice in menu:
            if choice == '9':
                print(f"{Fore.YELLOW}¡Hasta luego! 👋")
                break
            else:
                menu[choice][1]()
        else:
            print(f"{Fore.RED}Opción no válida. Intente de nuevo.")

if __name__ == '__main__':
    main()
