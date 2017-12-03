import json from 'rollup-plugin-json'
import coffee from 'rollup-plugin-coffee-script'
import builtins from 'rollup-plugin-node-builtins'
import resolve from 'rollup-plugin-node-resolve'
import commonjs from 'rollup-plugin-commonjs'

import uglify from 'rollup-plugin-uglify'
import { minify } from 'uglify-es'

import filesize from 'rollup-plugin-filesize'
import visualizer from 'rollup-plugin-visualizer'


const plugins = [
  json(),
  coffee(),
  builtins(),

  resolve({
    jsnext: true,
    extensions: ['.js', '.json', '.coffee'],
  }),
  
  commonjs({
    extensions: ['.js', '.json', '.coffee'],
    namedExports: {
      'crypto-js': [ 'algo', 'lib', 'mode', 'pad' ],
    }
  }),

  uglify({}, minify),
  filesize(),
  visualizer(),
];


export default [
  {
    input: 'lib/document.coffee',
    output: {
      name: 'PDFDocument',
      file: 'build/pdfkit.js',
      format: 'umd',
    },
    external: ['fontkit'],
    plugins: plugins,
  }, {
    input: 'node_modules/fontkit/index.js',
    output: {
      name: 'fontkit',
      file: 'build/fontkit.js',
      format: 'umd',
    },
    plugins: plugins,
  }
];
