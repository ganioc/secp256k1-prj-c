# FOO = bar
BUILD_DEBUG = yes
# unexport FOO
export FOO=FOO
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.o)

# cc = gcc

# main: main.o
# 	$(cc) -o main main.o

# main.o: main.c
# 	$(cc) -c $< -o $@

$(info $(FOO) $(origin FOO))
$(info $(BUILD_DEBUG) $(origin BUILD_DEBUG))
$(info $(shell FOO=$(FOO) printenv | grep FOO))

.PHONY = all clean

all: $(OBJS)
	gcc -o main $<

%.o: %.c
	$(COMPILE.C) -o $@ $<

clean:
	@rm -f src/*.o

