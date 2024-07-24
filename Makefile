
SUBDIRS := \
  zpoline \
  zpoline/apps/basic \
  apps/my_basic \
  apps/gpu_driver \
  test \

define FOREACH
for DIR in $(SUBDIRS); do \
  $(MAKE) -C $$DIR $(1); \
  done
endef

.PHONY: all
all:
	$(call FOREACH,)

.PHONY: clean
clean:
	$(call FOREACH,clean)

