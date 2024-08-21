# Temere
*A very rough, but functional python based anti-ransomware prototype*

# What does it do?
- Monitors Desktop, Documents, Downloads, Pictures, Music and Videos.
- Monitors for very high entropy writes (>0.8 Shannon Entropy) logging each.
- If >5 high-entropy writes are procured by one process in <2s then the process is killed, and reported to console.

# Future Changes?
- More ransomware activity heuristics for detection
- Faster response time to ransomware
- Response to low-entropy encryption methods, such as XOR.

  Please expect issues, if you use this. Although, it does work.


