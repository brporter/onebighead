import '@testing-library/jest-dom';

// Polyfill for HTMLDialogElement in jsdom
HTMLDialogElement.prototype.showModal = function() {
  this.setAttribute('open', '');
};

HTMLDialogElement.prototype.close = function() {
  this.removeAttribute('open');
};

