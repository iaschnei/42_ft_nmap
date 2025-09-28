# ---------------------------------------------------------------------------- #

SRCS		=	srcs/main.c \
				srcs/parsing.c srcs/load_targets.c

# ---------------------------------------------------------------------------- #

OBJS		=	$(SRCS:.c=.o)

DEPS		=	$(SRCS:.c=.d)

CC			=	gcc

INCL    	=	include

FLAGS		=	-Wall -Wextra -Werror -MMD -MP

NAME		=	ft_nmap

LDLIBS = -lpthread -lpcap

COLOR_GREEN	=	\033[1;32m
COLOR_RED	=	\033[1;31m
COLOR_BLUE	=	\033[3;36m
COLOR_PURP	=	\033[1;35m
COLOR_END	=	\033[0m

%.o: %.c
	@$(CC) $(FLAGS) -I $(INCL) -g -c $< -o $@
	@echo "$(COLOR_BLUE) || Compiling ($<)...$(COLOR_END)"

all: $(NAME)

$(NAME): $(OBJS)
	@$(CC) $(OBJS) $(LDLIBS) -o $(NAME)
	@echo "$(COLOR_GREEN) || Done !$(COLOR_END)"

clean:
	@rm -rf $(OBJS)
	@echo "$(COLOR_RED) || Cleaning files...$(COLOR_END)"

fclean: clean
	@rm -rf $(NAME) $(DEPS)
	@echo "$(COLOR_RED) || Cleaning library...$(COLOR_END)"

re: fclean all

.PHONY: re fclean all clean

-include $(DEPS)