%% Falcon signing - stacked zoom figure (top -> bottom)
%   1  full signing        2  whole f decode        3  f[0] decode
% Panels sit close with a small gap; each keeps its own x-axis (they are
% different zoom levels). The x10^k multiplier is moved to the RIGHT side of
% each panel so it does not sit below the axis and push the panels apart.
% First 100 samples of each are dropped. Add zoom arrows / a,b,c in MATLAB
% or the LaTeX caption yourself.

clear; clc;
DIR   = 'C:\Project\Falcon-SCA';
FILES = {'falcon_trace_sign_full', 'falcon_trace_decode1', 'falcon_trace_decode'};
SIG   = {'power_raw', 'power_mean', 'power_mean'};   % full=raw, decodes=mean
SKIP  = 100;                        % drop first 100 samples of each
COL   = [0.20 0.60 0.70];          % teal line
TITLES = {'Overview of Full Falcon Signature Power Trace', ...   % top
          'Overview of Decode Operation Power Trace', ...                    % middle
          'Overview of The First Decode Operation Power Trace'}; % bottom

% --- y-axis unit -------------------------------------------------------
% The scope measures VOLTAGE, but the .mat stores raw ADC counts. Keeping raw
% counts keeps the full range (~2e4, first plot goes high) AND keeps the
% x10^k on the y-axis (MATLAB shows it top-left, beside the axis).
RANGE_V       = 0.5;               % channel-A full-scale range (volts)
ADC_FULLSCALE = 32512;             % ps3000a max ADC count at +full scale
% To show millivolts instead (squashes the first plot to ~300 mV, no y10^k):
%   ADC_TO_MV = RANGE_V*1000/ADC_FULLSCALE;   YLAB = 'Voltage (mV)';
ADC_TO_MV     = 1;                 % raw ADC counts -> keeps higher range + y10^k
YLAB          = 'Power (ADC)';

% --- panel positions [left bottom width height]; small gap between them ---
L = 0.11;  W = 0.83;  H = 0.225;   % shorter panels -> bigger gap between them
POS = [L 0.700 W H;                % top    full signing
       L 0.395 W H;                % middle whole f decode
       L 0.090 W H];               % bottom f[0] decode

figure('Color','w','Position',[100 100 720 760]);
ax = gobjects(1,3);
for i = 1:3
    S = load(fullfile(DIR, [FILES{i} '.mat']));
    y = S.(SIG{i});

    % --- drop the trigger-LOW gaps and merge: keep only PC2-high samples ---
    % Uses the channel-B marker (pc2_marker) stored alongside the power. High =
    % an interesting op is running; low = idle gap between ops -> removed, and
    % the remaining high segments are concatenated back-to-back.
    if isfield(S, 'pc2_marker')
        m  = double(S.pc2_marker(:));
        hi = m > (min(m) + 0.5*(max(m) - min(m)));   % PC2 high threshold
        y  = y(hi);                                  % merge the high segments
    end

    y = y(SKIP+1:end) * ADC_TO_MV;             % skip first 100, scale to mV
    x = (1:numel(y)).';

    ax(i) = axes('Position', POS(i,:));
    plot(x, y, 'Color', COL, 'LineWidth', 0.5);
    grid on; box on; xlim([x(1) x(end)]);
    set(ax(i), 'FontSize', 13, 'GridAlpha', 0.25);
    title(ax(i), TITLES{i}, 'FontSize', 13, 'FontWeight', 'normal');

    % sample-count exponent: scale the ticks, hide the auto x10^k that sits
    % under the axis, and print our own x10^k on the RIGHT side instead.
    e = floor(log10(x(end)));
    ax(i).XAxis.Exponent = e;                          % ticks -> 2 4 6 8 ...
    ax(i).XAxis.SecondaryLabel.Visible = 'off';        % kill the bottom x10^k
    text(ax(i), 1.006, 0, sprintf('\\times10^{%d}', e), 'Units','normalized', ...
         'HorizontalAlignment','left', 'VerticalAlignment','bottom', 'FontSize',13);

    % make the ADC (y-axis) x10^4 the SAME size as the x10^k above (10 pt).
    % must be inside the loop so every panel is set, and after the plot so
    % MATLAB has already created the exponent label.
    ax(i).YAxis.SecondaryLabel.FontSize = 13;
end
% --- shared labels, pulled in close to the axes ---
xlabel(ax(3), 'Time in Samples', 'FontSize', 15);
ax(3).XLabel.Units = 'normalized';
ax(3).XLabel.Position(2) = -0.20;      % less negative = closer to the axis

ylabel(ax(2), YLAB, 'FontSize', 15);   % middle panel = vertical centre
ax(2).YLabel.Units = 'normalized';
ax(2).YLabel.Position(1) = -0.06;      % less negative = closer to the axis

% vector export for the paper (add arrows first if doing it in MATLAB)
% exportgraphics(gcf, 'falcon_zoom_stack.pdf', 'ContentType', 'vector');
