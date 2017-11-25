## 
## HSM lib test Makefile
## -------------------------------------------------------
#  $Id: Makefile 187 2012-01-27 15:57:50Z mlange $
#  -------------------------------------------------------

APP=polyhelper

# options
DATE  = $(shell /bin/date +%d.%m.%y)
_DATE = $(shell /bin/date +%d_%m_%y)

RD    = "\033[0;31m"
NC    = "\033[0m"


#directories
PRJDIR        = $(shell pwd)
OBJDIR        = obj
LCOVDIR       = lcov


INC_DIR   = src
SRC_DIR   = src


VPATH = $(SRC_DIR)

# tools 
CC = gcc
CXX = g++

# compiler / linker flags
CFLAGS= \
        -03 \
        -I $(INC_DIR)
CXXFLAGS=\
	-O3 \
        -I $(INC_DIR)

LDFLAGS=

# libraries to link against
LIBS +=  -lntl -lgmp

# source and header files
FILES = \
        main \


OBJECTS = $(addprefix $(OBJDIR)/, $(addsuffix .o, $(FILES)))
DEPENDS = $(addprefix $(OBJDIR)/, $(addsuffix .d, $(FILES)))

#--- how to create object and dependencie files from sources ---
$(OBJDIR)/%.o:%.cpp
	@echo $(RD)"    compiling $<"$(NC)
	$(CXX) $(CXXFLAGS) -c $< -o $@
	@echo $(RD)"    creating dependencies for $<"$(NC)
	$(CXX) $(CXXFLAGS) -MM -MT $(OBJDIR)/$*.o $<  >$(OBJDIR)/$*.d

# all
## make all  - creates software
# -------------------------------------------------------
all: $(OBJDIR) $(OBJECTS) 
	@echo $(RD)"    linking object files"$(NC)
	$(CXX) $(LDFLAGS) -o $(APP) $(OBJECTS) $(LIBS)

-include $(DEPENDS)


# create directories
$(OBJDIR):
	@echo $(RD)"    create $@"$(NC)
	@mkdir -p $@
	@chmod 775 $@


.PHONY: clean
clean:
	@rm -rf $(OBJDIR) $(LCOVDIR) $(APP)

# help
## make help - print this help
# -------------------------------------------------------
.PHONY: help
help:
	@sed -n '/^##/s/## //p' Makefile
