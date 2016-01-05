# Init
AC_INIT([nantools], [0.1.0], [i.ucar86@gmail.com])
AC_DEFINE([INFODUPS_VERSION], ["1.1.0"], [Version number of infodups])
AC_DEFINE([TSERIES_VERSION], ["1.0.0"], [Version number of tseries])
AC_DEFINE([_FILE_OFFSET_BITS], [64], [Force 64-bit functions])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_GNU_SOURCE
CFLAGS="$CFLAGS -pedantic -Wall -std=gnu99"

# Checks for programs
AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_AR

# Checks for libraries
AC_CHECK_LIB([pcap], [pcap_loop], [LIBS+=-lpcap], [AC_MSG_ERROR([libpcap required])])
AC_CHECK_LIB([pthread], [pthread_create], [THREADS=-pthread], [AC_MSG_ERROR([pthread required])])
AC_SUBST([THREADS])

# Checks for header files
AC_CHECK_HEADERS([pcap/pcap.h],, [AC_MSG_ERROR([<pcap/pcap.h> required])])
AC_CHECK_HEADERS([pthread.h],, [AC_MSG_ERROR([<pthread.h> required])])
AC_CHECK_HEADERS([fcntl.h],, [AC_MSG_ERROR([<fcntl.h> required])])
AC_CHECK_HEADERS([limits.h],, [AC_MSG_ERROR([<limits.h> required])])
AC_CHECK_HEADERS([sys/time.h],, [AC_MSG_ERROR([<sys/time.h> required])])
AC_CHECK_HEADERS([arpa/inet.h],, [AC_MSG_ERROR([<arpa/inet.h> required])])
AC_CHECK_HEADER_STDBOOL

# Checks for typedefs, structures, and compiler characteristics
AC_TYPE_SIZE_T
AC_C_INLINE

# Checks for library functions
AC_CHECK_FUNCS([gettimeofday],, [AC_MSG_ERROR([gettimeofday required])])
AC_CHECK_FUNCS([inet_ntoa],, [AC_MSG_ERROR([inet_ntoa required])])
AC_CHECK_FUNCS([strerror],, [AC_MSG_ERROR([strerror required])])
AC_CHECK_FUNCS([strtoull],, [AC_MSG_ERROR([strtoull required])])
AC_FUNC_FSEEKO
AC_FUNC_MALLOC
AC_FUNC_OBSTACK
AC_FUNC_REALLOC

# Output files
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_FILES([
  Makefile
  src/common/Makefile
  src/infodups/Makefile
  src/tseries/Makefile
])
AC_OUTPUT
