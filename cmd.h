#ifndef _COMMAND_H_
#define _COMMAND_H_

struct command_list {
	char *cmd;
	int  (*fun)(int, char **);
};

void cmdinit(void);
void prompt(void);
void prompt_raw(void);
void unfold_command(int, char *);
char *get_input_buffer(size_t *);

#define COMMAND(name)                                                    \
extern int cmd_ ## name (int, char **);                                  \
struct command_list name ## _command                                     \
    __attribute__ ((__section__(".command"))) = { #name, cmd_ ## name }; \
int cmd_ ## name (int argc, char **argv)

#endif /* _COMMAND_H_ */
