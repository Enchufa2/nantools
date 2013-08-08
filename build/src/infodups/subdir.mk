# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS_INFODUPS += \
../src/infodups/dups.c \
../src/infodups/pkt.c \
../src/infodups/worker.c \
../src/infodups/buffer.c \
../src/infodups/infodups.c 

OBJS_INFODUPS += \
./src/infodups/dups.o \
./src/infodups/pkt.o \
./src/infodups/worker.o \
./src/infodups/buffer.o \
./src/infodups/infodups.o 

C_DEPS_INFODUPS += \
./src/infodups/dups.d \
./src/infodups/pkt.d \
./src/infodups/worker.d \
./src/infodups/buffer.d \
./src/infodups/infodups.d 

OBJS += $(OBJS_INFODUPS)
C_DEPS += $(C_DEPS_INFODUPS)

# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
    @echo 'Building file: $<'
    @echo 'Invoking: GCC C Compiler'
    gcc $(CFLAGS) -c -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
    @echo 'Finished building: $<'
    @echo ' '
