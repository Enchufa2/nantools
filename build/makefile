-include ../makefile.init

RM := rm -rf
CFLAGS := -O3 -pedantic -Wall -fmessage-length=0 -std=gnu99 -MMD -MP

# All of the sources participating in the build are defined here
-include sources.mk
-include src/common/subdir.mk
-include src/infodups/subdir.mk
-include src/tseries/subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: infodups tseries

# Tool invocations
infodups: $(OBJS_COMMON)$(OBJS_INFODUPS)
    @echo 'Building target: $@'
    @echo 'Invoking: GCC C Linker'
    gcc -o "infodups" $(OBJS_COMMON)$(OBJS_INFODUPS)$(LIBS) -pthread
    @echo 'Finished building target: $@'
    @echo ' '

tseries: $(OBJS_COMMON)$(OBJS_TSERIES)
    @echo 'Building target: $@'
    @echo 'Invoking: GCC C Linker'
    gcc -o "tseries" $(OBJS_COMMON)$(OBJS_TSERIES)$(LIBS)
    @echo 'Finished building target: $@'
    @echo ' '

# Other Targets
clean:
    -$(RM) $(OBJS)$(C_DEPS)$(EXECUTABLES)
    -@echo ' '

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
