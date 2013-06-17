# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS_TSERIES += \
../src/tseries/DSTries.c \
../src/tseries/series.c \
../src/tseries/tseries.c 

OBJS_TSERIES += \
./src/tseries/DSTries.o \
./src/tseries/series.o \
./src/tseries/tseries.o 

C_DEPS_TSERIES += \
./src/tseries/DSTries.d \
./src/tseries/series.d \
./src/tseries/tseries.d 

OBJS += $(OBJS_TSERIES)
C_DEPS += $(C_DEPS_TSERIES)

# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc $(CFLAGS) -c -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '
