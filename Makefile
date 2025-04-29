SRC_DIR := src
OBJ_DIR := obj
# all src files
SRC := $(wildcard $(SRC_DIR)/*.c)
# all objects
PARSER_OBJ := $(OBJ_DIR)/y.tab.o $(OBJ_DIR)/lex.yy.o $(OBJ_DIR)/parse.o
# all binaries
BIN := example echo_server
# C compiler
CC  := gcc
# C PreProcessor Flag
CPPFLAGS := -Iinclude
# compiler flags
CFLAGS   := -g -Wall

default: all
all: example echo_server

example: $(PARSER_OBJ) $(OBJ_DIR)/example.o
	$(CC) $^ -o $@

$(SRC_DIR)/lex.yy.c: $(SRC_DIR)/lexer.l
	flex -o $@ $^

$(SRC_DIR)/y.tab.c: $(SRC_DIR)/parser.y
	yacc -d $^
	mv y.tab.c $@
	mv y.tab.h $(SRC_DIR)/y.tab.h

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

echo_server: $(PARSER_OBJ) $(OBJ_DIR)/echo_server.o
	$(CC) $(CFLAGS) $^ -o $@

$(OBJ_DIR):
	mkdir -p $@

clean:
	$(RM) $(OBJ) $(BIN) $(SRC_DIR)/lex.yy.c $(SRC_DIR)/y.tab.*
	$(RM) -r $(OBJ_DIR)

.PHONY: all clean default
