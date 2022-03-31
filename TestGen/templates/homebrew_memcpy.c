void homebrew_memcpy(void *dst, const void *src, size_t length) {
  char *d, *s;
  d = (char *)dst;
  s = (char *)src;
  while(length--) {
    *d++ = *s++;
  }
}