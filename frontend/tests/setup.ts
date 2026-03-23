import '@testing-library/jest-dom';

// Polyfill for window.matchMedia in jsdom
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
});

// Polyfill for HTMLDialogElement in jsdom
HTMLDialogElement.prototype.showModal = function() {
  this.setAttribute('open', '');
};

HTMLDialogElement.prototype.close = function() {
  this.removeAttribute('open');
};

