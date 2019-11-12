#include "mbed.h"

int main(void)
{
    printf("Hello World\r\n");
    printf("%s\n", MBED_CONF_APP_OUTPUT_UUID);
}
