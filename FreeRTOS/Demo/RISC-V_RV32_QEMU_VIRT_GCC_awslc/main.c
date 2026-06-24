/*
 * FreeRTOS V202212.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * https://www.FreeRTOS.org
 * https://github.com/FreeRTOS
 *
 */


/******************************************************************************
 * See https://www.freertos.org/freertos-on-qemu-mps2-an385-model.html for
 * instructions.
 *
 * This project provides two demo applications.  A simple blinky style project,
 * and a more comprehensive test and demo application.  The
 * mainCREATE_SIMPLE_BLINKY_DEMO_ONLY constant, defined in this file, is used to
 * select between the two.  The simply blinky demo is implemented and described
 * in main_blinky.c.  The more comprehensive test and demo application is
 * implemented and described in main_full.c.
 *
 * This file implements the code that is not demo specific, including the
 * hardware setup and FreeRTOS hook functions.
 *
 * Running in QEMU:
 * Use the following commands to start the application running in a way that
 * enables the debugger to connect, omit the "-s -S" to run the project without
 * the debugger:
 *
 * qemu-system-riscv32 -machine virt -smp 1 -nographic -bios none -serial stdio -kernel [path-to]/RTOSDemo.elf -s -S
 */

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"

/* Standard includes. */
#include <stdio.h>
#include <string.h>

/* This project provides two demo applications.  A simple blinky style demo
 * application, and a more comprehensive test and demo application.  The
 * mainCREATE_SIMPLE_BLINKY_DEMO_ONLY setting is used to select between the two.
 *
 * If mainCREATE_SIMPLE_BLINKY_DEMO_ONLY is 1 then the blinky demo will be built.
 * The blinky demo is implemented and described in main_blinky.c.
 *
 * If mainCREATE_SIMPLE_BLINKY_DEMO_ONLY is not 1 then the comprehensive test and
 * demo application will be built.  The comprehensive test and demo application is
 * implemented and described in main_full.c. */
#define mainCREATE_SIMPLE_BLINKY_DEMO_ONLY    0

/* Set to 1 to use direct mode and set to 0 to use vectored mode.
 * VECTOR MODE=Direct --> all traps into machine mode cause the pc to be set to the
 * vector base address (BASE) in the mtvec register.
 * VECTOR MODE=Vectored --> all synchronous exceptions into machine mode cause the
 * pc to be set to the BASE, whereas interrupts cause the pc to be set to the
 * address BASE plus four times the interrupt cause number.
 */
#define mainVECTOR_MODE_DIRECT                0

/* printf() output uses the UART.  These constants define the addresses of the
 * required UART registers. */
#define UART0_ADDRESS                         ( 0x40004000UL )
#define UART0_DATA                            ( *( ( ( volatile uint32_t * ) ( UART0_ADDRESS + 0UL ) ) ) )
#define UART0_STATE                           ( *( ( ( volatile uint32_t * ) ( UART0_ADDRESS + 4UL ) ) ) )
#define UART0_CTRL                            ( *( ( ( volatile uint32_t * ) ( UART0_ADDRESS + 8UL ) ) ) )
#define UART0_BAUDDIV                         ( *( ( ( volatile uint32_t * ) ( UART0_ADDRESS + 16UL ) ) ) )
#define TX_BUFFER_MASK                        ( 1UL )

/* Registers used to initialise the PLIC. */
#define mainPLIC_PENDING_0                    ( *( ( volatile uint32_t * ) 0x0C001000UL ) )
#define mainPLIC_PENDING_1                    ( *( ( volatile uint32_t * ) 0x0C001004UL ) )
#define mainPLIC_ENABLE_0                     ( *( ( volatile uint32_t * ) 0x0C002000UL ) )
#define mainPLIC_ENABLE_1                     ( *( ( volatile uint32_t * ) 0x0C002004UL ) )

extern void freertos_risc_v_trap_handler( void );
extern void freertos_vector_table( void );

/*
 * main_blinky() is used when mainCREATE_SIMPLE_BLINKY_DEMO_ONLY is set to 1.
 * main_full() is used when mainCREATE_SIMPLE_BLINKY_DEMO_ONLY is set to 0.
 */
extern void main_blinky( void );
extern void main_full( void );
extern void main_awslc( void );

/*
 * Only the comprehensive demo uses application hook (callback) functions.  See
 * https://www.FreeRTOS.org/a00016.html for more information.
 */
void vFullDemoTickHookFunction( void );
void vFullDemoIdleFunction( void );

/*-----------------------------------------------------------*/

void main( void )
{
    /* See https://www.freertos.org/freertos-on-qemu-mps2-an385-model.html for
     * instructions. */

    #if ( mainVECTOR_MODE_DIRECT == 1 )
    {
        __asm__ volatile ( "csrw mtvec, %0" : : "r" ( freertos_risc_v_trap_handler ) );
    }
    #else
    {
        __asm__ volatile ( "csrw mtvec, %0" : : "r" ( ( uintptr_t ) freertos_vector_table | 0x1 ) );
    }
    #endif

    main_awslc();
}
/*-----------------------------------------------------------*/

void vApplicationMallocFailedHook( void )
{
    /* vApplicationMallocFailedHook() will only be called if
     * configUSE_MALLOC_FAILED_HOOK is set to 1 in FreeRTOSConfig.h.  It is a hook
     * function that will get called if a call to pvPortMalloc() fails.
     * pvPortMalloc() is called internally by the kernel whenever a task, queue,
     * timer or semaphore is created using the dynamic allocation (as opposed to
     * static allocation) option.  It is also called by various parts of the
     * demo application.  If heap_1.c, heap_2.c or heap_4.c is being used, then the
     * size of the	heap available to pvPortMalloc() is defined by
     * configTOTAL_HEAP_SIZE in FreeRTOSConfig.h, and the xPortGetFreeHeapSize()
     * API function can be used to query the size of free heap space that remains
     * (although it does not provide information on how the remaining heap might be
     * fragmented).  See http://www.freertos.org/a00111.html for more
     * information. */
    printf( "\r\n\r\nMalloc failed\r\n" );
    portDISABLE_INTERRUPTS();

    for( ; ; )
    {
    }
}
/*-----------------------------------------------------------*/

void vApplicationIdleHook( void )
{
    /* vApplicationIdleHook() will only be called if configUSE_IDLE_HOOK is set
     * to 1 in FreeRTOSConfig.h.  It will be called on each iteration of the idle
     * task.  It is essential that code added to this hook function never attempts
     * to block in any way (for example, call xQueueReceive() with a block time
     * specified, or call vTaskDelay()).  If application tasks make use of the
     * vTaskDelete() API function to delete themselves then it is also important
     * that vApplicationIdleHook() is permitted to return to its calling function,
     * because it is the responsibility of the idle task to clean up memory
     * allocated by the kernel to any task that has since deleted itself. */
}
/*-----------------------------------------------------------*/

void vApplicationStackOverflowHook( TaskHandle_t pxTask,
                                    char * pcTaskName )
{
    ( void ) pcTaskName;
    ( void ) pxTask;

    /* Run time stack overflow checking is performed if
     * configCHECK_FOR_STACK_OVERFLOW is defined to 1 or 2.  This hook
     * function is called if a stack overflow is detected. */
    printf( "\r\n\r\nStack overflow in %s\r\n", pcTaskName );
    portDISABLE_INTERRUPTS();

    for( ; ; )
    {
    }
}
/*-----------------------------------------------------------*/

void vApplicationTickHook( void )
{
    /* No per-tick work needed for the AWS-LC self-test demo. */
}
/*-----------------------------------------------------------*/

void vApplicationDaemonTaskStartupHook( void )
{
    /* This function will be called once only, when the daemon task starts to
     * execute (sometimes called the timer task).  This is useful if the
     * application includes initialisation code that would benefit from executing
     * after the scheduler has been started. */
}
/*-----------------------------------------------------------*/

void vAssertCalled( const char * pcFileName,
                    uint32_t ulLine )
{
    volatile uint32_t ulSetToNonZeroInDebuggerToContinue = 0;

    /* Called if an assertion passed to configASSERT() fails.  See
     * http://www.freertos.org/a00110.html#configASSERT for more information. */

    printf( "ASSERT! Line %d, file %s\r\n", ( int ) ulLine, pcFileName );

    taskENTER_CRITICAL();
    {
        /* You can step out of this function to debug the assertion by using
         * the debugger to set ulSetToNonZeroInDebuggerToContinue to a non-zero
         * value. */
        while( ulSetToNonZeroInDebuggerToContinue == 0 )
        {
            __asm volatile ( "NOP" );
            __asm volatile ( "NOP" );
        }
    }
    taskEXIT_CRITICAL();
}
/*-----------------------------------------------------------*/

/* configUSE_STATIC_ALLOCATION is set to 1, so the application must provide an
 * implementation of vApplicationGetIdleTaskMemory() to provide the memory that is
 * used by the Idle task. */
void vApplicationGetIdleTaskMemory( StaticTask_t ** ppxIdleTaskTCBBuffer,
                                    StackType_t ** ppxIdleTaskStackBuffer,
                                    StackType_t * pulIdleTaskStackSize )
{
/* If the buffers to be provided to the Idle task are declared inside this
 * function then they must be declared static - otherwise they will be allocated on
 * the stack and so not exists after this function exits. */
    static StaticTask_t xIdleTaskTCB;
    static StackType_t uxIdleTaskStack[ configMINIMAL_STACK_SIZE ];

    /* Pass out a pointer to the StaticTask_t structure in which the Idle task's
     * state will be stored. */
    *ppxIdleTaskTCBBuffer = &xIdleTaskTCB;

    /* Pass out the array that will be used as the Idle task's stack. */
    *ppxIdleTaskStackBuffer = uxIdleTaskStack;

    /* Pass out the size of the array pointed to by *ppxIdleTaskStackBuffer.
     * Note that, as the array is necessarily of type StackType_t,
     * configMINIMAL_STACK_SIZE is specified in words, not bytes. */
    *pulIdleTaskStackSize = configMINIMAL_STACK_SIZE;
}
/*-----------------------------------------------------------*/

/* configUSE_STATIC_ALLOCATION and configUSE_TIMERS are both set to 1, so the
 * application must provide an implementation of vApplicationGetTimerTaskMemory()
 * to provide the memory that is used by the Timer service task. */
void vApplicationGetTimerTaskMemory( StaticTask_t ** ppxTimerTaskTCBBuffer,
                                     StackType_t ** ppxTimerTaskStackBuffer,
                                     uint32_t * pulTimerTaskStackSize )
{
/* If the buffers to be provided to the Timer task are declared inside this
 * function then they must be declared static - otherwise they will be allocated on
 * the stack and so not exists after this function exits. */
    static StaticTask_t xTimerTaskTCB;
    static StackType_t uxTimerTaskStack[ configTIMER_TASK_STACK_DEPTH ];

    /* Pass out a pointer to the StaticTask_t structure in which the Timer
     * task's state will be stored. */
    *ppxTimerTaskTCBBuffer = &xTimerTaskTCB;

    /* Pass out the array that will be used as the Timer task's stack. */
    *ppxTimerTaskStackBuffer = uxTimerTaskStack;

    /* Pass out the size of the array pointed to by *ppxTimerTaskStackBuffer.
     * Note that, as the array is necessarily of type StackType_t,
     * configMINIMAL_STACK_SIZE is specified in words, not bytes. */
    *pulTimerTaskStackSize = configTIMER_TASK_STACK_DEPTH;
}
/*-----------------------------------------------------------*/

/*
 * AWS-LC calls the C library malloc/free/calloc/realloc directly. Route them
 * to FreeRTOS heap_4 so all allocations come out of configTOTAL_HEAP_SIZE.
 *
 * malloc/realloc store the original size in a header word so realloc can copy
 * across, since pvPortFree doesn't expose the allocation size.
 */
#include <string.h>

void * malloc( size_t size )
{
    if( size == 0 )
    {
        return NULL;
    }
    size_t * p = ( size_t * ) pvPortMalloc( size + sizeof( size_t ) );
    if( p == NULL )
    {
        return NULL;
    }
    *p = size;
    return ( void * ) ( p + 1 );
}

void free( void * ptr )
{
    if( ptr == NULL )
    {
        return;
    }
    size_t * p = ( ( size_t * ) ptr ) - 1;
    vPortFree( p );
}

void * calloc( size_t nmemb, size_t size )
{
    size_t total = nmemb * size;
    if( nmemb != 0 && total / nmemb != size )
    {
        return NULL; /* overflow */
    }
    void * p = malloc( total );
    if( p != NULL )
    {
        memset( p, 0, total );
    }
    return p;
}

void * realloc( void * ptr, size_t size )
{
    if( ptr == NULL )
    {
        return malloc( size );
    }
    if( size == 0 )
    {
        free( ptr );
        return NULL;
    }
    size_t old_size = *( ( ( size_t * ) ptr ) - 1 );
    void * np = malloc( size );
    if( np == NULL )
    {
        return NULL;
    }
    memcpy( np, ptr, old_size < size ? old_size : size );
    free( ptr );
    return np;
}
/*-----------------------------------------------------------*/

/*
 * Minimal newlib syscall stubs. AWS-LC pulls in a few file-I/O symbols via
 * libc but the BORINGSSL_self_test path does not exercise them; these exist
 * to satisfy the link and to behave sensibly if anything calls them.
 *
 * _write is the actual stdout sink: route bytes to the QEMU virt NS16550
 * UART so printf() output is visible on the serial console.
 */
#include "ns16550.h"
#include "riscv-virt.h"

int _write( int fd, const char * buf, int len )
{
    ( void ) fd;
    struct device dev = { .addr = NS16550_ADDR };
    for( int i = 0; i < len; i++ )
    {
        vOutNS16550( &dev, ( unsigned char ) buf[ i ] );
    }
    return len;
}

int _read( int fd, char * buf, int len )      { ( void ) fd; ( void ) buf; ( void ) len; return 0; }
int _close( int fd )                          { ( void ) fd; return -1; }
int _lseek( int fd, int off, int w )          { ( void ) fd; ( void ) off; ( void ) w; return -1; }
int _fstat( int fd, void * st )               { ( void ) fd; ( void ) st; return -1; }
int _isatty( int fd )                         { ( void ) fd; return 1; }
int _kill( int pid, int sig )                 { ( void ) pid; ( void ) sig; return -1; }
int _getpid( void )                           { return 1; }

/*
 * _sbrk: AWS-LC never calls the libc allocator directly (we route through
 * pvPortMalloc above), but newlib's startup may still reference _sbrk. Give
 * it a tiny static pool just to satisfy the linker.
 */
extern char __heap_start[], __heap_end[];
void * _sbrk( int incr )
{
    static char fallback_heap[ 1024 ];
    static char * brk_ptr = fallback_heap;
    char * prev = brk_ptr;
    if( ( brk_ptr - fallback_heap ) + incr > ( int ) sizeof( fallback_heap ) )
    {
        return ( void * ) -1;
    }
    brk_ptr += incr;
    return prev;
}

/*
 * AWS-LC calls time(NULL) in a handful of corner paths (PKCS#7, X.509). The
 * BORINGSSL_self_test path doesn't reach them; return a fixed value to keep
 * the link happy if it ever does.
 */
#include <time.h>
time_t time( time_t * t )
{
    if( t != NULL )
    {
        *t = 0;
    }
    return 0;
}
/*-----------------------------------------------------------*/
