#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void change_memory(char *address)
{
    (void) address;

    return;
}

void validate_setter(char *address)
{
    (void) address;

    printf("Good!\n");

    return;
}

int main()
{
    char *buffer = malloc(256);

    for (int i = 0; i < 256; i++)
        buffer[i] = (char)i;

    change_memory(buffer);

    if (!strncmp(buffer + 128, "abcd1234", 8)) {
        validate_setter(buffer + 128);
    }

    free(buffer);
}
