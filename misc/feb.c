#include <stdio.h>

int main() {
    unsigned int eax_value;
    unsigned int temp_value;  // Variabel sementara untuk menyimpan nilai

    asm volatile (
        "fld1 \n\t"                    // Load constant 1.0 into ST(0)
        "fst %%st(1) \n\t"             // Copy ST(0) to ST(1)
        "fadd %%st(0), %%st(1) \n\t"   // ST(1) = ST(0) + ST(1)
        "fdiv %%st(1), %%st(0) \n\t"   // ST(0) = ST(0) / ST(1)
        "movl $0x534, %[temp] \n\t"    // Move 0x534 into temp_value
        "fild %[temp] \n\t"            // Load integer from temp_value into ST(0)
        "fxch \n\t"                    // Exchange ST(0) with ST(1)
        "fmul %%st(1), %%st(0) \n\t"   // ST(0) = ST(0) * ST(1)
        "fistp %[temp] \n\t"           // Store integer from ST(0) into temp_value
        "movl %[temp], %%eax \n\t"     // Move temp_value back to EAX
        "movl %%eax, %0 \n\t"          // Move the value of EAX into eax_value
        : "=r"(eax_value)              // Output operand (store EAX into eax_value)
        : [temp] "m"(temp_value)       // Input/output operand (temp_value in memory)
        : "%eax"                       // Clobbered register
    );

    // Output the value of EAX
    printf("%u\n", eax_value);

    return 0;
}
