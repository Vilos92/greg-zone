#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *const linuxdeploy_path = "/opt/linuxdeploy/AppRun";

int main(int argc, char *argv[]) {
  char *forwarded[argc + 1];
  int source_index = 1;
  int target_index = 1;

  forwarded[0] = (char *)linuxdeploy_path;
  if (argc > 1 && strcmp(argv[1], "--appimage-extract-and-run") == 0) {
    source_index = 2;
  }

  while (source_index < argc) {
    forwarded[target_index++] = argv[source_index++];
  }
  forwarded[target_index] = NULL;

  execv(linuxdeploy_path, forwarded);
  perror("execv linuxdeploy");
  return 127;
}
