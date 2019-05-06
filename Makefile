# FOO = bar
BUILD_DEBUG = yes
# unexport FOO
export FOO=FOO
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.o)
CFLAGS := -I./include
LDFLAGS := -L./lib -lsecp256k1
cc = gcc

$(info $(FOO) $(origin FOO))
$(info $(BUILD_DEBUG) $(origin BUILD_DEBUG))
$(info $(shell FOO=$(FOO) printenv | grep FOO))

.PHONY = all clean

all: $(OBJS)
	$(cc) $(LDFLAGS) -o main $^

%.o: %.c
	$(cc) $(CFLAGS) -c $< -o $@

clean:
	@rm -f src/*.o

