function generate_plots(TRAF_log,NOCS_log,Q_log)
    traffic = load(TRAF_log);
    NOCServ = load(NOCS_log);
    Queue = load(Q_log);
    traf = num2cell(traffic,1);
    NOCS = num2cell(NOCServ,1);
    Q = num2cell(Queue,1);
    subplot(2,1,1);
    for i = 1: length(traf{1})
        hold on;
        if(traf{2}(i) == 0)
            stem(traf{1}(i),traf{2}(i) + 1,'marker','*','color','green')
        elseif(traf{2}(i) == 1)
            stem(traf{1}(i),traf{2}(i),'marker','*','color','yellow')
        elseif(traf{2}(i) == 2)
            stem(traf{1}(i),traf{2}(i) - 1,'marker','*','color','blue')
        else
            stem(traf{1}(i),traf{2}(i)- 2,'marker','*','color','red')
        end
    end
    legend('G=N-S(G)','Y=N-S(Y)','B=W-E(G)','R= W-E(Y)');
    hold off;
    xlabel('time');
    ylabel('Traffic State');
    subplot(2,1,2);
    for i = 1: length(NOCS{1})
        hold on;
        if(NOCS{2}(i) == 0)
            plot(NOCS{1}(i),NOCS{3}(i),'*','color','green');
        elseif(NOCS{2}(i) == 1)
            plot(NOCS{1}(i),NOCS{3}(i),'*','color','yellow');
        elseif(NOCS{2}(i) == 2)
            plot(NOCS{1}(i),NOCS{3}(i),'*','color','blue');
        elseif(NOCS{2}(i) == 3)
            plot(NOCS{1}(i),NOCS{3}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('NOCS');

    figure;
    subplot(5,1,1);
    for i = 1: length(traf{1})
        hold on;
        if(traf{2}(i) == 0)
            stem(traf{1}(i),traf{2}(i) + 1,'marker','*','color','green')
        elseif(traf{2}(i) == 1)
            stem(traf{1}(i),traf{2}(i),'marker','*','color','yellow')
        elseif(traf{2}(i) == 2)
            stem(traf{1}(i),traf{2}(i) - 1,'marker','*','color','blue')
        else
            stem(traf{1}(i),traf{2}(i)- 2,'marker','*','color','red')
        end
    end
    legend('G=N-S(G)','Y=N-S(Y)','B=W-E(G)','R= W-E(Y)');
    hold off;
    xlabel('time');
    ylabel('Traffic State');
    subplot(5,1,2);
    for i = 1: length(NOCS{1})
        hold on;
        if(NOCS{2}(i) == 0)
            plot(NOCS{1}(i),NOCS{4}(i),'*','color','green');
        elseif(NOCS{2}(i) == 1)
            plot(NOCS{1}(i),NOCS{4}(i),'*','color','yellow');
        elseif(NOCS{2}(i) == 2)
            plot(NOCS{1}(i),NOCS{4}(i),'*','color','blue');
        elseif(NOCS{2}(i) == 3)
            plot(NOCS{1}(i),NOCS{4}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('NOCS-N');

    subplot(5,1,3);
    for i = 1: length(NOCS{1})
        hold on;
        if(NOCS{2}(i) == 0)
            plot(NOCS{1}(i),NOCS{6}(i),'*','color','green');
        elseif(NOCS{2}(i) == 1)
            plot(NOCS{1}(i),NOCS{6}(i),'*','color','yellow');
        elseif(NOCS{2}(i) == 2)
            plot(NOCS{1}(i),NOCS{6}(i),'*','color','blue');
        elseif(NOCS{2}(i) == 3)
            plot(NOCS{1}(i),NOCS{6}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('NOCS-S');


    subplot(5,1,5);
    for i = 1: length(NOCS{1})
        hold on;
        if(NOCS{2}(i) == 0)
            plot(NOCS{1}(i),NOCS{5}(i),'*','color','green');
        elseif(NOCS{2}(i) == 1)
            plot(NOCS{1}(i),NOCS{5}(i),'*','color','yellow');
        elseif(NOCS{2}(i) == 2)
            plot(NOCS{1}(i),NOCS{5}(i),'*','color','blue');
        elseif(NOCS{2}(i) == 3)
            plot(NOCS{1}(i),NOCS{5}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('NOCS-W');

    subplot(5,1,4);
    for i = 1: length(NOCS{1})
        hold on;
        if(NOCS{2}(i) == 0)
            plot(NOCS{1}(i),NOCS{7}(i),'*','color','green');
        elseif(NOCS{2}(i) == 1)
            plot(NOCS{1}(i),NOCS{7}(i),'*','color','yellow');
        elseif(NOCS{2}(i) == 2)
            plot(NOCS{1}(i),NOCS{7}(i),'*','color','blue');
        elseif(NOCS{2}(i) == 3)
            plot(NOCS{1}(i),NOCS{7}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('NOCS-E');

    figure;
    subplot(3,1,1);
    for i = 1: length(Q{1})
        hold on;
        if(Q{2}(i) == 0)
            plot(Q{1}(i),Q{3}(i),'*','color','green');
        elseif(Q{2}(i) == 1)
            plot(Q{1}(i),Q{3}(i),'*','color','yellow');
        elseif(Q{2}(i) == 2)
            plot(Q{1}(i),Q{3}(i),'*','color','blue');
        elseif(Q{2}(i) == 3)
            plot(Q{1}(i),Q{3}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('Q1 size');


    subplot(3,1,2);
    for i = 1: length(Q{1})
        hold on;
        if(Q{2}(i) == 0)
            plot(Q{1}(i),Q{4}(i),'*','color','green');
        elseif(Q{2}(i) == 1)
            plot(Q{1}(i),Q{4}(i),'*','color','yellow');
        elseif(Q{2}(i) == 2)
            plot(Q{1}(i),Q{4}(i),'*','color','blue');
        elseif(Q{2}(i) == 3)
            plot(Q{1}(i),Q{4}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('Q2 size');

    subplot(3,1,3);
    for i = 1: length(Q{1})
        hold on;
        if(Q{2}(i) == 0)
            plot(Q{1}(i),Q{5}(i),'*','color','green');
        elseif(Q{2}(i) == 1)
            plot(Q{1}(i),Q{5}(i),'*','color','yellow');
        elseif(Q{2}(i) == 2)
            plot(Q{1}(i),Q{5}(i),'*','color','blue');
        elseif(Q{2}(i) == 3)
            plot(Q{1}(i),Q{5}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('Q3 size');

    figure;
    subplot(3,1,1);
    for i = 1: length(Q{1})
        hold on;
        if(Q{2}(i) == 0)
            plot(Q{1}(i),Q{6}(i),'*','color','green');
        elseif(Q{2}(i) == 1)
            plot(Q{1}(i),Q{6}(i),'*','color','yellow');
        elseif(Q{2}(i) == 2)
            plot(Q{1}(i),Q{6}(i),'*','color','blue');
        elseif(Q{2}(i) == 3)
            plot(Q{1}(i),Q{6}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('Q4 size');


    subplot(3,1,2);
    for i = 1: length(Q{1})
        hold on;
        if(Q{2}(i) == 0)
            plot(Q{1}(i),Q{7}(i),'*','color','green');
        elseif(Q{2}(i) == 1)
            plot(Q{1}(i),Q{7}(i),'*','color','yellow');
        elseif(Q{2}(i) == 2)
            plot(Q{1}(i),Q{7}(i),'*','color','blue');
        elseif(Q{2}(i) == 3)
            plot(Q{1}(i),Q{7}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('Q5 size');

    subplot(3,1,3);
    for i = 1: length(Q{1})
        hold on;
        if(Q{2}(i) == 0)
            plot(Q{1}(i),Q{8}(i),'*','color','green');
        elseif(Q{2}(i) == 1)
            plot(Q{1}(i),Q{8}(i),'*','color','yellow');
        elseif(Q{2}(i) == 2)
            plot(Q{1}(i),Q{8}(i),'*','color','blue');
        elseif(Q{2}(i) == 3)
            plot(Q{1}(i),Q{8}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('Q6 size');


    figure;
    subplot(3,1,1);
    for i = 1: length(Q{1})
        hold on;
        if(Q{2}(i) == 0)
            plot(Q{1}(i),Q{9}(i),'*','color','green');
        elseif(Q{2}(i) == 1)
            plot(Q{1}(i),Q{9}(i),'*','color','yellow');
        elseif(Q{2}(i) == 2)
            plot(Q{1}(i),Q{9}(i),'*','color','blue');
        elseif(Q{2}(i) == 3)
            plot(Q{1}(i),Q{9}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('Q7 size');


    subplot(3,1,2);
    for i = 1: length(Q{1})
        hold on;
        if(Q{2}(i) == 0)
            plot(Q{1}(i),Q{10}(i),'*','color','green');
        elseif(Q{2}(i) == 1)
            plot(Q{1}(i),Q{10}(i),'*','color','yellow');
        elseif(Q{2}(i) == 2)
            plot(Q{1}(i),Q{10}(i),'*','color','blue');
        elseif(Q{2}(i) == 3)
            plot(Q{1}(i),Q{10}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('Q8 size');

    subplot(3,1,3);
    for i = 1: length(Q{1})
        hold on;
        if(Q{2}(i) == 0)
            plot(Q{1}(i),Q{11}(i),'*','color','green');
        elseif(Q{2}(i) == 1)
            plot(Q{1}(i),Q{11}(i),'*','color','yellow');
        elseif(Q{2}(i) == 2)
            plot(Q{1}(i),Q{11}(i),'*','color','blue');
        elseif(Q{2}(i) == 3)
            plot(Q{1}(i),Q{11}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('Q9 size');

    figure;
    subplot(3,1,1);
    for i = 1: length(Q{1})
        hold on;
        if(Q{2}(i) == 0)
            plot(Q{1}(i),Q{12}(i),'*','color','green');
        elseif(Q{2}(i) == 1)
            plot(Q{1}(i),Q{12}(i),'*','color','yellow');
        elseif(Q{2}(i) == 2)
            plot(Q{1}(i),Q{12}(i),'*','color','blue');
        elseif(Q{2}(i) == 3)
            plot(Q{1}(i),Q{12}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('Q10 size');


    subplot(3,1,2);
    for i = 1: length(Q{1})
        hold on;
        if(Q{2}(i) == 0)
            plot(Q{1}(i),Q{13}(i),'*','color','green');
        elseif(Q{2}(i) == 1)
            plot(Q{1}(i),Q{13}(i),'*','color','yellow');
        elseif(Q{2}(i) == 2)
            plot(Q{1}(i),Q{13}(i),'*','color','blue');
        elseif(Q{2}(i) == 3)
            plot(Q{1}(i),Q{13}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('Q11 size');

    subplot(3,1,3);
    for i = 1: length(Q{1})
        hold on;
        if(Q{2}(i) == 0)
            plot(Q{1}(i),Q{14}(i),'*','color','green');
        elseif(Q{2}(i) == 1)
            plot(Q{1}(i),Q{14}(i),'*','color','yellow');
        elseif(Q{2}(i) == 2)
            plot(Q{1}(i),Q{14}(i),'*','color','blue');
        elseif(Q{2}(i) == 3)
            plot(Q{1}(i),Q{14}(i),'*','color','red');
        end
    end
    hold off;
    xlabel('time');
    ylabel('Q12 size');
end





