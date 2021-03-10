// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#include "direct_serial_output.h"
#include "hal/serial_api.h"
#include <stdio.h>
#include <stdarg.h>	

#if (MBED_CONF_MBED_BOOTLOADER_TRACE == USE_DIRECT_SERIAL_OUTPUT)

# define MAX_STRING_REPRESENTATION_SIZE 20

static serial_t uart = {};

static bool initialized = false;

//format specifier list.

/*Currently suported specifies: {'c','d','u','s','x','X',i'} */
static char format_specifiers[] = {'c','d','u','s','x','X','i','e','E','f','g','G','o','p','n','z'};
static char hex_representation[]= "0123456789ABCDEF";
static char num_string_buff[MAX_STRING_REPRESENTATION_SIZE]; 

static char* convert_to_string(unsigned int num, int base) 
{ 
    char *ptr = &num_string_buff[MAX_STRING_REPRESENTATION_SIZE-1];
    *ptr = '\0';  
    do 
    { 
        ptr--;
        *ptr = hex_representation[num % base]; 
        num /= base; 
    } while (num != 0);
    
    return(ptr); 
}


static void output_string_to_serial(const char *str) 
{
    while (*str) {
      serial_putc(&uart, *str);
      str++;
    }
}

/**
 * @brief Initialization serial port if needed.
 *.
 */
static void direct_serial_output_init()
{
    if (initialized == false)
    {
        serial_init(&uart, STDIO_UART_TX, STDIO_UART_RX);
#if MBED_CONF_PLATFORM_STDIO_BAUD_RATE
        serial_baud(&uart, MBED_CONF_PLATFORM_STDIO_BAUD_RATE);
#endif

        initialized = true;
    }
}


/**
 * @brief Function that directly outputs to serial port in blocking mode.
 *
 * @param string outputed to serial port.
 */
void direct_serial_output_process(const char *format, ...)
{
    char c, *str;
    int i;
    bool format_specifier_detected = false;

    direct_serial_output_init();

    va_list arg;
    va_start (arg, format);

    while (*format) {

        if (*format == '%') { // required format identifer char

            //find the argument in the argument array. It doensn't have to be necessary the next char (i.e %llu)
            while ((format_specifier_detected == false) && (*format)) {
                format++;
                for (size_t j = 0; j < sizeof(format_specifiers); j++) {
                    if ((*format) == format_specifiers[j]) {
                        format_specifier_detected = true;
                        break;
                    }
                }
            }

            if (format_specifier_detected == true) {

                //format identifier detected, process it
                switch (*format) {
                    case 'c': //process single character
                        c = va_arg(arg, int);
                        serial_putc(&uart, c);
                        break;

                    case 'i':
                    case 'd':  //process integer
                        i = va_arg(arg, int );
                        if(i < 0) 
                        { 
                            i = -i;
                            serial_putc(&uart,'-');
                        } 
                        str = convert_to_string(i, 10);
                        output_string_to_serial(str);
                        break;

                    case 'u': //process unsigned integer
                        str = convert_to_string(va_arg(arg, unsigned int ), 10);
                        output_string_to_serial(str);
                        break;

                    case 's': //process string
                        str = va_arg(arg,char*); //Fetch string
                        output_string_to_serial(str);
                        break; 

                    case 'x': //process hex format
                    case 'X':
                        str = convert_to_string(va_arg(arg,unsigned int),16);
                        output_string_to_serial(str);
                        break;

                    default: //unsupported specifier, just fetch it
                        va_arg(arg, int); 
                        break;
                } 

                format_specifier_detected = false;

            } else {
                //reached NULL character after % without specifier. stop processing.
                goto finish;
            }

        } else {
            serial_putc(&uart, *format);
        }

        format++;
    }

finish:
    va_end(arg);
}

#endif // MBED_BOOTLOADER_USE_DIRECT_SERIAL_OUTPUT

