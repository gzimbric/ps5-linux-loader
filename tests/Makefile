CC ?= cc
CFLAGS ?= -std=c17 -O2 -Wall -Wextra -Werror

TESTS := test_shellcode_kernel_args test_resume_result_1160 test_break_hv_1160

.PHONY: check clean

check: $(TESTS)
	@for test in $(TESTS); do \
		echo "RUN $$test"; \
		./$$test; \
	done

test_shellcode_kernel_args: test_shellcode_kernel_args.c \
		../shellcode_kernel/shellcode_kernel_args.h \
		../shellcode_kernel_1160/shellcode_kernel_args_validate.h
	$(CC) $(CFLAGS) -I../shellcode_kernel -o $@ $<

test_resume_result_1160: test_resume_result_1160.c \
		../shellcode_kernel/shellcode_kernel_args.h \
		../shellcode_kernel_1160/shellcode_kernel_args_validate.h \
		../shellcode_kernel_1160/resume_result_1160_validate.h
	$(CC) $(CFLAGS) -I../shellcode_kernel -o $@ $<

test_break_hv_1160: test_break_hv_1160.c \
		../shellcode_break_hv/break_hv.c \
		../shellcode_break_hv/break_hv_params.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TESTS)
