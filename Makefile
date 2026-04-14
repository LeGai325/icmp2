CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11

OBJS = icmp_sonar_lab.o common.o capture_engine.o packet_builder.o scheduler.o classifier.o

icmp_sonar_lab: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

clean:
	rm -f $(OBJS) icmp_sonar_lab
