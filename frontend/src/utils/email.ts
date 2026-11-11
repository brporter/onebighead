export const EMAIL_PATTERN = '[^\\s@]+@[^\\s@]+\\.[^\\s@]+';
export const EMAIL_MAX_LENGTH = 320;
const emailPattern = new RegExp(`^${EMAIL_PATTERN}$`);
export const isValidEmail = (value: string) => value.length <= EMAIL_MAX_LENGTH && emailPattern.test(value);
