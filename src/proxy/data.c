/* XXX from common/data.cc */

#include <ctype.h>

int hex2num(char c)
{
    if (isdigit(c))
        return c - '0';
    else {
        char d = tolower(c);

        if (d >= 'a' && d <= 'f')
            return d - 'a' + 10;

        return 0;
    }
}
