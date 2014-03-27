'use strict';

module.exports = function(grunt) {

  // Project configuration.
  grunt.initConfig({
    jshint: {
      all: [
        'Gruntfile.js',
        './*.js'
      ],
      options: {
        jshintrc: '.jshintrc'
      }
    },

    // Unit tests.
    nodeunit: {
      tests: ['tests/*js']
    }

  });

  // These plugins provide necessary tasks.
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-contrib-nodeunit');

  // By default, lint and run all tests.
  grunt.registerTask('default', ['jshint', 'nodeunit']);

};
