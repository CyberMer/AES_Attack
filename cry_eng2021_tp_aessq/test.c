
#include <stdio.h>
#include <stdint.h>
uint8_t xtime(uint8_t p)
{
	uint8_t m = p >> 7;

	m ^= 1;
	m -= 1;
	m &= 0x1B;

	return ((p << 1) ^ m);
}


void main() {
  printf("Verification of xtime with m=1\n");
  uint8_t t = xtime(0x6);
  printf("xtime(3)= 0x%x\n", t);

  printf("Verification of xtime with m=0\n");
  uint8_t t2 = xtime(0x2D);

  printf("xtime(0)= 0x%x\n", t2); 


}
