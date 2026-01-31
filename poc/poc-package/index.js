/**
 * Dependency Confusion PoC Package
 * Author: OFJAAAH
 *
 * This is a placeholder module. The actual PoC code runs during preinstall.
 * This file exists to make the package a valid npm module.
 */

module.exports = {
  name: 'dependency-confusion-poc',
  author: 'OFJAAAH',
  message: 'This package is a security research PoC for dependency confusion.',
  isVulnerable: true,

  // Informational function
  info: function() {
    console.log('Dependency Confusion PoC by OFJAAAH');
    console.log('If this package was installed, your system may be vulnerable.');
    return this;
  }
};
