#ifndef GL_SELFTEST_H
#define GL_SELFTEST_H

/* Offline verification entry point.
 *
 * `main()` dispatches here before anything else when argv[1] is
 * "--crypto-selftest" or "--offsets-verify"; with no flag the engine goes
 * straight to run_exploit() exactly as before, so this cannot perturb the
 * timing-sensitive exploit path.  It exists because the AEAD container can
 * only be trusted if the crypto is checked against the RFC vectors *on the
 * target*, not merely on the machine that wrote it. */
int gl_selftest_main(int argc, char **argv);

#endif
