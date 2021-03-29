#ifndef __IMX_CAAM_H__
#define __IMX_CAAM_H__

/* Return 32bit long RNG */
int imx_rand(void);

/* User add entropy function. */
void imx_trusty_rand_add_entropy(const void *buf, size_t len);

#endif
