#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
    if (fork()) {
        printf("parent: %d\n", getpid());
    } else {
        printf("child: %d\n", getpid());
    }
    sleep(10000);
}
