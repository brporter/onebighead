import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import ItemFlagRibbon from '../src/components/item/ItemFlagRibbon';
import { UserFlag } from '../src/utils/types';

describe('ItemFlagRibbon', () => {
  describe('snapshots', () => {
    it('should render null for None flag', () => {
      const { container } = render(<ItemFlagRibbon userFlag={UserFlag.None} />);
      expect(container).toMatchSnapshot();
    });

    it('should render null for Have flag', () => {
      const { container } = render(<ItemFlagRibbon userFlag={UserFlag.Have} />);
      expect(container).toMatchSnapshot();
    });

    it('should render Want ribbon', () => {
      const { container } = render(<ItemFlagRibbon userFlag={UserFlag.Want} />);
      expect(container).toMatchSnapshot();
    });

    it('should render Trade/Sell ribbon', () => {
      const { container } = render(<ItemFlagRibbon userFlag={UserFlag.TradeOrSell} />);
      expect(container).toMatchSnapshot();
    });
  });

  describe('rendering', () => {
    it('should not render anything for UserFlag.None', () => {
      const { container } = render(<ItemFlagRibbon userFlag={UserFlag.None} />);
      expect(container.firstChild).toBeNull();
    });

    it('should not render anything for UserFlag.Have', () => {
      const { container } = render(<ItemFlagRibbon userFlag={UserFlag.Have} />);
      expect(container.firstChild).toBeNull();
    });

    it('should render "I Want This!" for UserFlag.Want', () => {
      render(<ItemFlagRibbon userFlag={UserFlag.Want} />);
      expect(screen.getByText('I Want This!')).toBeInTheDocument();
    });

    it('should render "For Trade/Sale" for UserFlag.TradeOrSell', () => {
      render(<ItemFlagRibbon userFlag={UserFlag.TradeOrSell} />);
      expect(screen.getByText('For Trade/Sale')).toBeInTheDocument();
    });

    it('should use want class for Want flag', () => {
      const { container } = render(<ItemFlagRibbon userFlag={UserFlag.Want} />);
      const ribbon = container.querySelector('.itemFlagRibbon');
      expect(ribbon).toHaveClass('itemFlagRibbon--want');
    });

    it('should use trade class for TradeOrSell flag', () => {
      const { container } = render(<ItemFlagRibbon userFlag={UserFlag.TradeOrSell} />);
      const ribbon = container.querySelector('.itemFlagRibbon');
      expect(ribbon).toHaveClass('itemFlagRibbon--trade');
    });
  });
});
