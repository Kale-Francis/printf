#!/bin/bash

#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>

#define BUFFER_SIZE 1024

void rot13(char *str) {
    char *p = str;
    while (*p) {
        if (isalpha(*p)) {
            char base = islower(*p) ? 'a' : 'A';
            *p = (char)(((*p - base + 13) % 26) + base);
        }
        p++;
    }
}

int _printf(const char *format, ...)
{
    int i = 0, count = 0, buffer_index = 0;
    char buffer[BUFFER_SIZE];
    va_list args;
    char c;
    const char *s;
    char rot13_str[100];
    unsigned long num;
    unsigned long ptr;
    int j, digit, field_width, precision, length_modifier;
    int zero_flag, minus_flag, plus_flag, space_flag, hash_flag;
    
    if (!format)
        return (-1);

    va_start(args, format);

    while (format && format[i])
    {
        // Reset flags and modifiers
        field_width = 0;
        precision = -1;
        length_modifier = 0;
        zero_flag = 0;
        minus_flag = 0;
        plus_flag = 0;
        space_flag = 0;
        hash_flag = 0;

        // Check for flags
        while (format[i] == '-' || format[i] == '0' || format[i] == '+' || format[i] == ' ' || format[i] == '#')
        {
            if (format[i] == '-')
                minus_flag = 1;
            else if (format[i] == '0')
                zero_flag = 1;
            else if (format[i] == '+')
                plus_flag = 1;
            else if (format[i] == ' ')
                space_flag = 1;
            else if (format[i] == '#')
                hash_flag = 1;
            i++;
        }

        // Check for field width
        while (format[i] >= '0' && format[i] <= '9')
        {
            field_width = field_width * 10 + (format[i] - '0');
            i++;
        }

        // Check for precision
        if (format[i] == '.')
        {
            i++;
            precision = 0;
            while (format[i] >= '0' && format[i] <= '9')
            {
                precision = precision * 10 + (format[i] - '0');
                i++;
            }
        }

        // Check for length modifiers
        while (format[i] == 'l' || format[i] == 'h')
        {
            if (format[i] == 'l')
                length_modifier = 1;
            else if (format[i] == 'h')
                length_modifier = 2;
            i++;
        }

        if (format[i] == '%')
        {
            i++;
            switch (format[i])
            {
                case 'c':
                    c = (char)va_arg(args, int);
                    if (buffer_index >= BUFFER_SIZE - 1)
                    {
                        write(1, buffer, buffer_index);
                        count += buffer_index;
                        buffer_index = 0;
                    }
                    buffer[buffer_index++] = c;
                    count++;
                    break;
                case 's':
                    s = va_arg(args, const char *);
                    if (!s)
                        s = "(null)";
                    while (*s)
                    {
                        if (buffer_index >= BUFFER_SIZE - 1)
                        {
                            write(1, buffer, buffer_index);
                            count += buffer_index;
                            buffer_index = 0;
                        }
                        buffer[buffer_index++] = *s++;
                        count++;
                    }
                    break;
                case '%':
                    if (buffer_index >= BUFFER_SIZE - 1)
                    {
                        write(1, buffer, buffer_index);
                        count += buffer_index;
                        buffer_index = 0;
                    }
                    buffer[buffer_index++] = '%';
                    count++;
                    break;
                case 'd':
                case 'i':
                    num = va_arg(args, int);
                    char num_buffer[100];
                    int num_len = snprintf(num_buffer, sizeof(num_buffer), "%d", num);
                    if (field_width > num_len)
                    {
                        int padding = field_width - num_len;
                        if (minus_flag)
                        {
                            for (j = 0; j < num_len; j++)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = num_buffer[j];
                                count++;
                            }
                            while (padding-- > 0)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = ' ';
                            }
                        }
                        else
                        {
                            while (padding-- > 0)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = zero_flag ? '0' : ' ';
                            }
                            for (j = 0; j < num_len; j++)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = num_buffer[j];
                                count++;
                            }
                        }
                    }
                    else
                    {
                        for (j = 0; j < num_len; j++)
                        {
                            if (buffer_index >= BUFFER_SIZE - 1)
                            {
                                write(1, buffer, buffer_index);
                                count += buffer_index;
                                buffer_index = 0;
                            }
                            buffer[buffer_index++] = num_buffer[j];
                            count++;
                        }
                    }
                    break;
                case 'u':
                case 'o':
                case 'x':
                case 'X':
                    if (format[i] == 'u')
                        num = va_arg(args, unsigned int);
                    else if (format[i] == 'o')
                        num = va_arg(args, unsigned int);
                    else if (format[i] == 'x')
                        num = va_arg(args, unsigned int);
                    else
                        num = va_arg(args, unsigned int);

                    // Convert number to string here (you may need custom conversion functions)
                    // For simplicity, assuming snprintf or similar function for demonstration
                    char num_buf[100];
                    int num_len = snprintf(num_buf, sizeof(num_buf), 
                        format[i] == 'x' ? "%x" : format[i] == 'X' ? "%X" : "%u", num);
                    if (field_width > num_len)
                    {
                        int padding = field_width - num_len;
                        if (minus_flag)
                        {
                            for (j = 0; j < num_len; j++)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = num_buf[j];
                                count++;
                            }
                            while (padding-- > 0)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = ' ';
                            }
                        }
                        else
                        {
                            while (padding-- > 0)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = zero_flag ? '0' : ' ';
                            }
                            for (j = 0; j < num_len; j++)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = num_buf[j];
                                count++;
                            }
                        }
                    }
                    else
                    {
                        for (j = 0; j < num_len; j++)
                        {
                            if (buffer_index >= BUFFER_SIZE - 1)
                            {
                                write(1, buffer, buffer_index);
                                count += buffer_index;
                                buffer_index = 0;
                            }
                            buffer[buffer_index++] = num_buf[j];
                            count++;
                        }
                    }
                    break;
                case 'p':
                    ptr = va_arg(args, unsigned long);
                    char ptr_buf[100];
                    int ptr_len = snprintf(ptr_buf, sizeof(ptr_buf), "0x%lx", ptr);
                    if (field_width > ptr_len)
                    {
                        int padding = field_width - ptr_len;
                        if (minus_flag)
                        {
                            for (j = 0; j < ptr_len; j++)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = ptr_buf[j];
                                count++;
                            }
                            while (padding-- > 0)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = ' ';
                            }
                        }
                        else
                        {
                            while (padding-- > 0)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = zero_flag ? '0' : ' ';
                            }
                            for (j = 0; j < ptr_len; j++)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = ptr_buf[j];
                                count++;
                            }
                        }
                    }
                    else
                    {
                        for (j = 0; j < ptr_len; j++)
                        {
                            if (buffer_index >= BUFFER_SIZE - 1)
                            {
                                write(1, buffer, buffer_index);
                                count += buffer_index;
                                buffer_index = 0;
                            }
                            buffer[buffer_index++] = ptr_buf[j];
                            count++;
                        }
                    }
                    break;
                case 'S':
                    s = va_arg(args, const char *);
                    if (!s)
                        s = "(null)";
                    while (*s)
                    {
                        if (buffer_index >= BUFFER_SIZE - 1)
                        {
                            write(1, buffer, buffer_index);
                            count += buffer_index;
                            buffer_index = 0;
                        }
                        if (*s < 32 || *s >= 127)
                            snprintf(buffer + buffer_index, BUFFER_SIZE - buffer_index, "\\x%02X", (unsigned char)*s);
                        else
                            buffer[buffer_index++] = *s;
                        s++;
                    }
                    count += buffer_index;
                    break;
                case 'b':
                    num = va_arg(args, unsigned int);
                    char bin_buf[100];
                    int bin_len = 0;
                    if (num == 0)
                        bin_buf[bin_len++] = '0';
                    else
                    {
                        while (num)
                        {
                            bin_buf[bin_len++] = (num & 1) ? '1' : '0';
                            num >>= 1;
                        }
                        for (int k = 0; k < bin_len / 2; k++)
                        {
                            char tmp = bin_buf[k];
                            bin_buf[k] = bin_buf[bin_len - k - 1];
                            bin_buf[bin_len - k - 1] = tmp;
                        }
                    }
                    bin_buf[bin_len] = '\0';
                    if (field_width > bin_len)
                    {
                        int padding = field_width - bin_len;
                        if (minus_flag)
                        {
                            for (j = 0; j < bin_len; j++)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = bin_buf[j];
                                count++;
                            }
                            while (padding-- > 0)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = ' ';
                            }
                        }
                        else
                        {
                            while (padding-- > 0)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = zero_flag ? '0' : ' ';
                            }
                            for (j = 0; j < bin_len; j++)
                            {
                                if (buffer_index >= BUFFER_SIZE - 1)
                                {
                                    write(1, buffer, buffer_index);
                                    count += buffer_index;
                                    buffer_index = 0;
                                }
                                buffer[buffer_index++] = bin_buf[j];
                                count++;
                            }
                        }
                    }
                    else
                    {
                        for (j = 0; j < bin_len; j++)
                        {
                            if (buffer_index >= BUFFER_SIZE - 1)
                            {
                                write(1, buffer, buffer_index);
                                count += buffer_index;
                                buffer_index = 0;
                            }
                            buffer[buffer_index++] = bin_buf[j];
                            count++;
                        }
                    }
                    break;
                default:
                    break;
            }
            i++;
        }
        else
        {
            if (buffer_index >= BUFFER_SIZE - 1)
            {
                write(1, buffer, buffer_index);
                count += buffer_index;
                buffer_index = 0;
            }
            buffer[buffer_index++] = format[i++];
            count++;
        }
    }
    if (buffer_index > 0)
    {
        write(1, buffer, buffer_index);
        count += buffer_index;
    }

    va_end(args);
    return (count);
}
