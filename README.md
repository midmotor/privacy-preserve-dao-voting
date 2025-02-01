# privacy-preserve-dao-voting
A privacy-preserving DAO voting system that leverages homomorphic encryption and zero-knowledge proofs (ZKPs) to ensure secure, verifiable, and anonymous voting while maintaining voter transparency and integrity.  

This repository offers two different systems using ZKPs:
1. One based on Bulletproof and Sigma protocols.
2. Another based on Groth16.

The results were obtained from an Intel(R) Core(TM) i5-9400 CPU running at 2.90GHz.

| **Name**     | **#Vote Box** | **Generation [ms]** | **Verification [ms]** | **#Constraints** |
|--------------|---------------|---------------------|-----------------------|------------------|
| Tx (Sigma)   | 3             | 14.9                | 12.5                  | -                |
| Tx (Groth16) | 3             | 114                 | 0.77                  | 26209            |
| Tx (Sigma)   | 4             | 20.1                | 16.3                  | -                |
| Tx (Groth16) | 4             | 191                 | 0.79                  | 34945            |
| Tx (Sigma)   | 5             | 24.6                | 20.4                  | -                |
| Tx (Groth16) | 5             | 203                 | 0.81                  | 43681            |
| Tx (Sigma)   | 6             | 28.8                | 23.8                  | -                |
| Tx (Groth16) | 6             | 209                 | 0.82                  | 52417            |

Details will be added..