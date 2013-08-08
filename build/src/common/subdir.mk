# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS_COMMON += \
../src/common/eth.c \
../src/common/ip.c \
../src/common/tcp.c \
../src/common/udp.c \
../src/common/utils.c 

OBJS_COMMON += \
./src/common/eth.o \
./src/common/ip.o \
./src/common/tcp.o \
./src/common/udp.o \
./src/common/utils.o 

C_DEPS_COMMON += \
./src/common/eth.d \
./src/common/ip.d \
./src/common/tcp.d \
./src/common/udp.d \
./src/common/utils.d 

OBJS += $(OBJS_COMMON)
C_DEPS += $(C_DEPS_COMMON)

# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
    @echo 'Building file: $<'
    @echo 'Invoking: GCC C Compiler'
    gcc $(CFLAGS) -c -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
    @echo 'Finished building: $<'
    @echo ' '
