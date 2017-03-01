/*****************************************************************************
 *
 * Copyright 2013 Silei Zhang
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ****************************************************************************/
/*
 * Machine dependent part of mth thread.
 */

#define SAVE_REG      \
	push	%rbp; \
	push	%rbx; \
	push	%r12; \
	push	%r13; \
	push	%r14; \
	push	%r15

#define RESTORE_REG   \
	pop	%r15; \
	pop	%r14; \
	pop	%r13; \
	pop	%r12; \
	pop	%rbx; \
	pop	%rbp

/* int get_task_trace(void **buffer, int size, void *stack) */
	.text
	.globl get_task_trace
	.type  get_task_trace, @function
get_task_trace:
	.cfi_startproc
	push    %rbx
	mov     %rsp, %rbx
	mov     %rdx, %rsp
	call    backtrace
	mov     %rbx, %rsp
	pop     %rbx
	retq
	.cfi_endproc

	.globl _t_start
	.type  _t_start, @function
	/* old sp, ip, sp */
_t_start:
	mov	%rsp, %rax
	mov	%rsi, %rsp
	push	%rdx
	push	$1f
	push	%rdi
	SAVE_REG

	mov	%rax, %rsp
	retq
1:
	pop	%rdi
	call	_t_stopped
	retq

	.globl _t_swtch
	.type  _t_swtch, @function
	/* old sp, new sp */
_t_swtch:
	SAVE_REG

	cmp	$0, %rdi
	je	1f
	mov	%rsp, 0(%rdi)
1:
	mov	0(%rsi), %rsp
	RESTORE_REG
	retq

	.globl _sched_start
	.type _sched_start, @function
_sched_start:
	SAVE_REG
	mov	%rsp, 0(%rdi)
	call	zthyield

	.globl _t_exit
	.type  _t_exit, @function
_t_exit:
	mov	%rdi, %rsp
	RESTORE_REG
	retq
